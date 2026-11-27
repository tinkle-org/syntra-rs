"""Unified Syntra 1.0 implementation evidence, not a conformance declaration.

Examples (repo root, PyYAML from scripts/requirements-evidence.txt):
  python3 scripts/conformance_evidence.py
  python3 scripts/conformance_evidence.py --output /tmp/new-evidence --run-local corpus

Local context and carrier fixtures are checked separately from supplemental
execution. TCP, WS and WSS are carriers of one protocol.
A Cargo exit or zero matching tests is not execution proof. Exit 0 means the
requested implementation checks succeeded, never formal conformance. No remote
operations are performed.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

sys.dont_write_bytecode = True

import yaml

from context_probe import rust_tokens
from local_inputs import FIXTURES, ROOT, digest, regular_file
from local_yaml import load_yaml
from protocol_contract import verify as verify_protocol
from manifest_adapters import (IMPLEMENTATION_WIRE_CONTRACT, SCENARIO_FIXTURE, SUPPLEMENTAL_SCENARIOS,
                               execute_supplemental, verify_scenario_fixture)


LOCAL_LANES = {
    "corpus": "sc_wire_vectors_decode",
    "echo": "sc_echo",
}
NATIVE_LOCAL_LANES = {
    # Partial lifecycle probes, not complete enrollment/crash/device matrices.
    # These do not establish formal conformance.
    "enrollment-preready": "enrollment::tests::wss_same_principal_and_current_enrollment_are_required_before_ready",
    "enrollment-revocation": "enrollment::tests::wss_revocation_cuts_off_protected_dispatch_delivery_and_reconnect",
}
CHANNEL_LANES = {
    "kernel-contexts": ("syntra-core --lib", "secure_channel::context_tests::four_candidate_context_and_prologue_fixtures"),
    "wss-context": ("syntra-core --test connection_records", "wss_context_uses_candidate_syntra_1_0_bytes"),
    "native-binding": ("syntra-net --features tls-rustls --test wss", "invalid_endpoints_and_carrier_mismatches_do_not_open_socket"),
    "native-tls13": ("syntra-net --features tls-rustls --test wss", "wss_server_rejects_tls12_client_before_authentication"),
    "loopback-ws": ("syntra-net --features websocket --test websocket", "ws_rejects_non_loopback_and_secure_carrier"),
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_transcriptions(root=ROOT):
    """Check local Protobuf and WS fixture inputs, not runtime behavior."""
    corpus_origin = FIXTURES / "protobuf-vectors.yaml"
    corpus = regular_file(root, corpus_origin)
    # Pin the historical b99f56b blob, allowing checkout line endings only.
    if digest(corpus.replace(b"\r\n", b"\n")) != "614e7ae45cd1739f3e0bc66b89b5d657ba607856104b59d73d93fbe8ade15360":
        raise ValueError("historical Protobuf corpus drift")
    gold = {row['id']: row for row in load_yaml(corpus)['vectors']}
    unknown_suffix = gold['GOLD-PROT-UNKNOWN-FIELD-01']['frame_hex'].removeprefix(gold['GOLD-PROT-REQ-01']['frame_hex'])
    origin = FIXTURES / "transport.yaml"
    source = regular_file(root, origin)
    transport = load_yaml(source)
    fixtures = {row["id"]: row for row in transport["fixtures"]}
    if len(fixtures) != len(transport["fixtures"]):
        raise ValueError("duplicate transport fixture ID")
    hello_origin = FIXTURES / "ws-no-length-prefix.hex"
    hello = regular_file(root, hello_origin)
    if not re.fullmatch(rb"(?:[0-9a-f]{2})+(?:\r?\n)?", hello):
        raise ValueError("VEC-WS-009 hello fixture drift")
    good = bytes.fromhex(hello.decode("ascii"))
    if len(good) >= 128 or digest(good) != fixtures["websocket/VEC-WS-009"]["frame_sha256"]:
        raise ValueError("VEC-WS-009 hello fixture drift")
    ping = fixtures["websocket/VEC-WS-005"]
    close = fixtures["websocket/VEC-WS-006"]
    expected = {
        "NO_LENGTH_PREFIX_GOOD_HEX": good.hex(), "UNKNOWN_FIELD_SUFFIX_HEX": unknown_suffix,
        "VARINT_PREFIXED_HEX": (bytes([len(good)]) + good).hex(),
        "U32_PREFIXED_HEX": (len(good).to_bytes(4, "big") + good).hex(), "SUFFIXED_HEX": good.hex() + "00",
        "PING_WIRE_HEX": ping["server_wire_hex"], "PONG_WIRE_HEX": ping["client_wire_hex"],
        "CLOSE_CLIENT_WIRE_HEX": close["client_wire_hex"],
        "CLOSE_HOST_WIRE_HEX": close["server_wire_hex"],
    }
    name = "tests/interoperability/vectors.rs"
    text = regular_file(root, name).decode("utf-8")
    tokens = [token[0] for token in rust_tokens(text)]
    actual = {}
    for i, key in enumerate(tokens):
        if not key.endswith("_HEX") or tokens[i - 1] != "const":
            continue
        declaration = " ".join(tokens[i - 2:i + 7])
        literal = re.fullmatch(r'pub const \w+_HEX : & str = "([0-9a-f]+)" ;', declaration)
        if not literal or key in actual:
            raise ValueError(f"handwritten WS vector transcription drift: {key}")
        actual[key] = literal[1]
    if actual != expected:
        raise ValueError("handwritten WS vector transcription drift")
    close_codes = fixtures["websocket/VEC-WS-007"]
    expected_codes = set(close_codes["mapping"].values())
    expected_codes.add(int(close["server_wire_hex"][-4:], 16))
    table = re.search(r"CLOSE_CODE_TABLE:.*?= &\[(.*?)\];", text, re.S)
    reserved = re.search(r"RESERVED_CLOSE_CODES:.*?= &\[(.*?)\];", text)
    if not table or {int(code) for code in re.findall(r"\((\d+),", table[1])} != expected_codes:
        raise ValueError("handwritten WS close-code transcription drift")
    if not reserved or list(map(int, re.findall(r"\d+", reserved[1]))) != close_codes["reserved"]:
        raise ValueError("handwritten WS reserved-code transcription drift")
    maximum = transport["default_max_frame_bytes"]
    bound = re.search(r"MAX_FRAME_BYTES: usize = ([0-9_]+);", text)
    if not bound or int(bound[1].replace("_", "")) != maximum:
        raise ValueError("handwritten envelope bound transcription drift")
    return {"kind": "fixture_transcription_only", "verdict": "PASS", "formal_conformance": False,
            "source": name, "source_sha256": digest(text.encode()),
            "origins": {origin.as_posix(): digest(source), hello_origin.as_posix(): digest(hello),
                        corpus_origin.as_posix(): digest(corpus)}}


def implementation_identity(root):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, timeout=30)
    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    files = {}
    for raw in sorted(set(names) - {b""}):
        name = raw.decode("utf-8")
        path = root / name
        if path.is_symlink():
            files[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            files[name] = digest(path.read_bytes())
        else:
            files[name] = "MISSING"
    return {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "dirty": bool(git("status", "--porcelain", "--untracked-files=all").strip()),
        "worktree_sha256": digest(canonical(files)), "files": files,
        "cargo_lock_sha256": digest((root / "Cargo.lock").read_bytes()),
        "rust_toolchain_sha256": digest((root / "rust-toolchain.toml").read_bytes()),
    }


def local_verdict(returncode, output, test):
    summaries = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", output)
    # Exact one-test proof, not exit status alone; ignored/filtered tests do not pass.
    if returncode:
        return "FAIL", "command failed (including compile/harness failures)"
    if summaries == [("0", "0", "1")]:
        return "SKIP", "exact test was ignored"
    if summaries == [("1", "0", "0")] and re.search(rf"^test {re.escape(test)} \.\.\. ok$", output, re.M):
        return "PASS", "one exact supplemental test executed successfully"
    return "NOT_EXECUTED", "no unambiguous single-test execution proof"


def run_local(lane, output_dir, root=ROOT):
    """Run a supplemental local lane and return its verdict and artifact metadata."""
    if lane in SUPPLEMENTAL_SCENARIOS:
        return execute_supplemental(lane, output_dir, local_verdict, root)
    if lane in CHANNEL_LANES:
        target, test = CHANNEL_LANES[lane]
    elif lane in NATIVE_LOCAL_LANES:
        test = NATIVE_LOCAL_LANES[lane]
        target = "syntra-net --features tls-rustls,native-enrollment --lib"
    else:
        test = LOCAL_LANES[lane]
        target = "syntra-runtime --test conformance_runner"
    command = ["cargo", "test", "--locked", "--no-default-features", "-p", *target.split(), test,
               "--", "--exact", "--show-output", "--color", "never"]
    log = output_dir / f"local-{lane}.log"
    result = {"lane": lane, "kind": "supplemental_local_test", "formal_conformance": False,
              "command": command, "RUSTUP_TOOLCHAIN": "1.89.0", "test": test}
    try:
        # Logs stay on disk; a large compiler log must not become a truncated PASS.
        with log.open("x", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                       env={**os.environ, "RUSTUP_TOOLCHAIN": "1.89.0"}, timeout=300)
        text = log.read_text(encoding="utf-8")
        verdict, reason = local_verdict(completed.returncode, text, test)
        result["exit_code"] = completed.returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        verdict, reason = "NOT_EXECUTED", f"execution could not complete: {type(error).__name__}"
    result.update(verdict=verdict, reason=reason, artifact=log.name,
                  artifact_sha256=digest(log.read_bytes()) if log.is_file() else None)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    lanes = LOCAL_LANES.keys() | NATIVE_LOCAL_LANES.keys() | CHANNEL_LANES.keys() | SUPPLEMENTAL_SCENARIOS.keys()
    parser.add_argument("--run-local", action="append", choices=sorted(lanes), default=[],
                        help="repeat supplemental local validation lanes")
    parser.add_argument("--output", type=Path, help="NEW artifact directory, never overwrites evidence")
    args = parser.parse_args()
    if args.run_local and not args.output:
        parser.error("--run-local requires --output for reproducible command logs")
    if args.output:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("evidence output must be a new directory")
        if args.output.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("evidence output must be outside the implementation worktree")
    before = implementation_identity(ROOT)
    verify_scenario_fixture(ROOT, before["files"].get(SCENARIO_FIXTURE.as_posix()))
    scope = verify_protocol()
    transcriptions = verify_transcriptions()
    if args.output:
        args.output.mkdir(exist_ok=False)
    local = [run_local(lane, args.output) for lane in dict.fromkeys(args.run_local)]
    after = implementation_identity(ROOT)
    changed_files = sorted(name for name in before.get("files", {}).keys() | after.get("files", {}).keys()
                           if before.get("files", {}).get(name) != after.get("files", {}).get(name))
    if before != after:
        for row in local:
            if row["verdict"] == "PASS":
                row.update(verdict="NOT_EXECUTED", reason="observation retained, but implementation changed during execution; rerun on a stable snapshot")
    report = {
        "format_version": 3, "kind": "implementation_evidence_not_conformance_declaration",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "formal_conformance_claimed": False,
        "implementation_wire_contract": IMPLEMENTATION_WIRE_CONTRACT,
        "scope": scope,
        "implementation": {"before": before, "after": after, "python": platform.python_version(), "pyyaml": yaml.__version__},
        "worktree_changed_during_run": before != after,
        "worktree_changed_files": changed_files,
        "supplemental_results": local,
        "fixture_verification": transcriptions,
        "external_gates": {key: {"verdict": "NOT_EXECUTED", "reason": reason} for key, reason in {
            "formal_conformance": "no independent formal conformance assessment executed; implementation checks and local lanes are supplemental",
            "physical_ios_android": "no physical-device lifecycle or budget harness executed",
            "browser": "no real browser scenario executed",
            "direct_host_tls13_wss": "local host observations alone do not establish independent full carrier/lifecycle validation",
            "independent_noise_vectors": "context/prologue fixtures are not independent handshake or directional record vectors",
            "device_budgets_and_soak": "no predeclared physical-device energy/latency/soak budget measurements executed",
            "independent_security_review": "requires independent human review",
        }.items()},
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        (args.output / "report.json").write_text(encoded, encoding="utf-8")
        print(json.dumps({"artifact": str(args.output / "report.json"),
                          "kind": report["kind"], "formal_conformance_claimed": False,
                          "supplemental_results": local}))
    else:
        print(encoded, end="")
    if any(row["verdict"] != "PASS" for row in local) or before != after:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError, subprocess.SubprocessError) as error:
        sys.exit(f"Evidence tooling failed (no conformance verdict): {error}")
