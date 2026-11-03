"""Read Cargo's declared package set and isolated production dependency graphs.

Run from the repository root: python3 scripts/cargo_contracts.py isolation
or python3 scripts/cargo_contracts.py package. Never enables workspace-wide
features or dev dependencies to prove a default production dependency boundary.
Graph inspection is not compilation or proof that the OS performs no I/O.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = "1.88.0"
ISOLATED_PACKAGES = ("syntra-core", "syntra-runtime", "syntra-transport")
FORBIDDEN_PACKAGES = re.compile(
    r"^(?:mio|socket2|http|http-body|httparse|h2|hyper(?:-.*)?|reqwest|"
    r"(?:tokio-)?(?:native-tls|rustls|tungstenite)(?:-.*)?|rustls(?:-.*)?|"
    r"openssl(?:-.*)?|quinn(?:-.*)?|ws_stream_wasm|rusqlite|libsqlite3-sys|"
    r"sqlite(?:-.*)?|sqlx(?:-.*)?|fs2)$"
)
FORBIDDEN_FEATURES = {
    "tokio": {"net"},
    "web-sys": {"WebSocket"},
    "syntra-runtime": {"file-store"},
    "syntra-transport": {"tcp", "websocket", "reconnect", "native-enrollment"},
}


def cargo(arguments, root=ROOT, *, capture=True):
    return subprocess.run(
        ["cargo", *arguments], cwd=root, check=True, text=True,
        capture_output=capture, timeout=300,
        env={**os.environ, "RUSTUP_TOOLCHAIN": TOOLCHAIN},
    )


def workspace_packages(root=ROOT):
    metadata = json.loads(cargo(["metadata", "--locked", "--no-deps", "--format-version", "1"], root).stdout)
    members = set(metadata["workspace_members"])
    return {package["name"]: package for package in metadata["packages"] if package["id"] in members}


def graph_violations(text, package):
    """Parse cargo tree's explicit {p}|{f} format, failing closed on empty output."""
    seen, violations = set(), []
    for line in text.splitlines():
        match = re.fullmatch(r"(\S+) v[^|]+\|([^|]*?)(?: \(\*\))?", line)
        if not match:
            raise ValueError(f"unrecognized cargo tree row: {line!r}")
        name, features = match.groups()
        seen.add(name)
        if FORBIDDEN_PACKAGES.fullmatch(name):
            violations.append(f"{package}: default production graph includes {name}")
        for feature in set(features.split(",")) & FORBIDDEN_FEATURES.get(name, set()):
            violations.append(f"{package}: default production graph enables {name}/{feature}")
    if package not in seen:
        raise ValueError(f"missing root {package} in dependency graph (empty/incorrect selection)")
    return sorted(set(violations))


def isolation(root=ROOT):
    packages = workspace_packages(root)
    missing = set(ISOLATED_PACKAGES) - packages.keys()
    if missing:
        raise ValueError(f"package migration is incomplete: missing {sorted(missing)}")
    failures = []
    for target in (None, "wasm32-unknown-unknown"):
        for package in ISOLATED_PACKAGES:
            # Deliberately omit --no-default-features: this checks shipped defaults.
            # A separate command per root avoids workspace/integration unification.
            command = ["tree", "--locked", "-p", package, "--edges", "normal,build",
                       "--prefix", "none", "--format", "{p}|{f}"]
            if target:
                command += ["--target", target]
            text = cargo(command, root).stdout
            violations = graph_violations(text, package)
            failures += [f"{target or 'host'}: {value}" for value in violations]
            print(json.dumps({"package": package, "target": target or "host", "command": ["cargo", *command],
                              "dev_dependencies": False, "verdict": "FAIL" if violations else "PASS",
                              "graph": text, "violations": violations}))
    if failures:
        raise ValueError("\n".join(failures))


def package_workspace(root=ROOT):
    packages = workspace_packages(root)
    publishable = sorted(name for name, package in packages.items() if package.get("publish") != [])
    if not publishable:
        raise ValueError("no publishable workspace packages selected")
    # Unpublished test support must never be forced into release packaging.
    print(json.dumps({"kind": "package_contents_not_build_verification", "packages": publishable}), flush=True)
    for name in publishable:
        cargo(["package", "--locked", "-p", name, "--list"], root, capture=False)
        cargo(["package", "--locked", "-p", name, "--no-verify"], root, capture=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=("isolation", "package"))
    args = parser.parse_args()
    (isolation if args.lane == "isolation" else package_workspace)()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        sys.exit(f"Cargo contract check failed: {error}")
