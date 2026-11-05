"""Read Cargo's declared package set and isolated production dependency graphs.

Run from the repository root: python3 scripts/cargo_contracts.py LANE, where LANE
is isolation, websocket, managed-websocket, http, cross-carrier-candidate or package.
Graph checks never enable
workspace-wide features or dev dependencies.
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
ISOLATED_PACKAGES = ("syntra-core", "syntra-runtime", "syntra-net")
FORBIDDEN_PACKAGES = re.compile(
    r"^(?:mio|socket2|http|http-body|httparse|h2|hyper(?:-.*)?|reqwest|"
    r"(?:tokio-)?(?:native-tls|rustls|tungstenite)(?:-.*)?|rustls(?:-.*)?|"
    r"openssl(?:-.*)?|quinn(?:-.*)?|ws_stream_wasm|rusqlite|libsqlite3-sys|"
    r"sqlite(?:-.*)?|sqlx(?:-.*)?|fs2)$"
)
FORBIDDEN_FEATURES = {
    "syntra-core": {"http-candidate"},
    "tokio": {"net"},
    "web-sys": {"WebSocket"},
    "syntra-runtime": {"file-store"},
    "syntra-net": {"tcp", "http", "websocket", "tls-rustls", "reconnect", "managed", "proxy", "native-enrollment", "cross-carrier-candidate"},
}
TLS_PACKAGES = re.compile(
    r"^(?:(?:tokio-)?native-tls(?:-.*)?|(?:tokio-)?rustls(?:-.*)?|"
    r"openssl(?:-.*)?|security-framework(?:-.*)?|schannel|webpki(?:-.*)?)$"
)
TLS_FEATURES = {
    "tokio-tungstenite": {"native-tls", "native-tls-vendored", "__rustls-tls", "rustls-tls-native-roots", "rustls-tls-webpki-roots"},
    "tungstenite": {"native-tls", "native-tls-vendored", "__rustls-tls", "rustls-tls-native-roots", "rustls-tls-webpki-roots"},
}
STATE_PACKAGES = re.compile(r"^(?:rusqlite|libsqlite3-sys|sqlite(?:-.*)?|sqlx(?:-.*)?|fs2)$")
WEBSOCKET_PACKAGES = re.compile(r"^(?:(?:tokio-)?tungstenite|ws_stream_wasm|http|httparse)$")


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


def graph_violations(text, package, *, no_tls_features=None):
    """Parse cargo tree's explicit {p}|{f} format, failing closed on empty output."""
    seen, violations, root_features = {}, [], set()
    forbidden_packages = FORBIDDEN_PACKAGES
    forbidden_features = FORBIDDEN_FEATURES
    scope = "default"
    if no_tls_features is not None:
        no_tls_features = set(no_tls_features)
        if "cross-carrier-candidate" in no_tls_features:
            # Require its TCP implication without selecting TCP on its behalf.
            no_tls_features.add("tcp")
        forbidden_packages = TLS_PACKAGES
        forbidden_features = {**TLS_FEATURES, "syntra-core": {"http-candidate"},
                              "syntra-runtime": {"file-store"},
                              "syntra-net": FORBIDDEN_FEATURES["syntra-net"] - no_tls_features}
        if "http" in no_tls_features:
            forbidden_features["syntra-core"] = set()
        scope = ",".join(sorted(no_tls_features)) + " (TLS-free)"
    for line in text.splitlines():
        match = re.fullmatch(r"(\S+) v[^|]+\|([^|]*?)(?: \(\*\))?", line)
        if not match:
            raise ValueError(f"unrecognized cargo tree row: {line!r}")
        name, features = match.groups()
        seen.setdefault(name, set()).update(features.split(","))
        if name == package:
            root_features.update(features.split(","))
        forbidden = forbidden_packages.fullmatch(name)
        if no_tls_features is not None:
            forbidden = forbidden or STATE_PACKAGES.fullmatch(name)
            if "websocket" not in no_tls_features:
                forbidden = forbidden or WEBSOCKET_PACKAGES.fullmatch(name)
        if forbidden:
            violations.append(f"{package}: {scope} production graph includes {name}")
        for feature in set(features.split(",")) & forbidden_features.get(name, set()):
            violations.append(f"{package}: {scope} production graph enables {name}/{feature}")
    if package not in seen:
        raise ValueError(f"missing root {package} in dependency graph (empty/incorrect selection)")
    if no_tls_features is not None and not no_tls_features <= root_features:
        raise ValueError(f"TLS-free graph did not enable syntra-net features: {sorted(no_tls_features - root_features)}")
    if no_tls_features is not None and "http" in no_tls_features:
        if "http-candidate" not in seen.get("syntra-core", set()):
            raise ValueError("HTTP candidate graph did not enable syntra-core/http-candidate")
    return sorted(set(violations))


def isolation(root=ROOT):
    packages = workspace_packages(root)
    missing = set(ISOLATED_PACKAGES) - packages.keys()
    if missing:
        raise ValueError(f"workspace package set is incomplete: missing {sorted(missing)}")
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


def tls_free_graph(features, root=ROOT):
    """Inspect selected production dependencies without test TLS fixtures."""
    command = ["tree", "--locked", "-p", "syntra-net", "--no-default-features",
               "--features", ",".join(features), "--edges", "normal,build",
               "--prefix", "none", "--format", "{p}|{f}"]
    text = cargo(command, root).stdout
    violations = graph_violations(text, "syntra-net", no_tls_features=features)
    print(json.dumps({"package": "syntra-net", "features": list(features),
                      "command": ["cargo", *command], "dev_dependencies": False,
                      "verdict": "FAIL" if violations else "PASS", "graph": text,
                      "violations": violations}))
    if violations:
        raise ValueError("\n".join(violations))


def websocket(root=ROOT):
    tls_free_graph(("websocket",), root)


def managed_websocket(root=ROOT):
    # managed/proxy imply tcp; managed also implies reconnect.
    tls_free_graph(("managed", "websocket", "proxy", "tcp", "reconnect"), root)


def http(root=ROOT):
    """Candidate HTTP/HTTPS uses application TLS; no TLS implementation is implied."""
    tls_free_graph(("http",), root)
    tls_free_graph(("managed", "http", "proxy", "tcp", "reconnect"), root)
    tls_free_graph(("managed", "http", "websocket", "proxy", "tcp", "reconnect"), root)


def cross_carrier_candidate(root=ROOT):
    """Keep the candidate opt-in separate from carrier and lifecycle selection."""
    tls_free_graph(("cross-carrier-candidate",), root)
    # Provider WSS must not imply a TLS implementation, HTTP or managed runtime.
    tls_free_graph(("cross-carrier-candidate", "websocket"), root)
    tls_free_graph(("cross-carrier-candidate", "managed", "websocket", "proxy", "tcp", "reconnect"), root)
    tls_free_graph(("cross-carrier-candidate", "managed", "http", "websocket", "proxy", "tcp", "reconnect"), root)


def package_workspace(root=ROOT):
    packages = workspace_packages(root)
    publishable = sorted(name for name, package in packages.items() if package.get("publish") != [])
    if not publishable:
        raise ValueError("no publishable workspace packages selected")
    # Unpublished test support must never be forced into release packaging.
    # List contents only: even --no-verify archives resolve registry dependencies
    # for their lockfiles, before the new workspace versions have been published.
    # Release-plz verifies packaged builds in dependency order during publishing.
    print(json.dumps({"kind": "package_contents_not_build_verification", "packages": publishable}), flush=True)
    for name in publishable:
        cargo(["package", "--locked", "-p", name, "--list"], root, capture=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=("isolation", "websocket", "managed-websocket", "http", "cross-carrier-candidate", "package"))
    args = parser.parse_args()
    {"isolation": isolation, "websocket": websocket, "managed-websocket": managed_websocket,
     "http": http, "cross-carrier-candidate": cross_carrier_candidate, "package": package_workspace}[args.lane]()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        sys.exit(f"Cargo contract check failed: {error}")
