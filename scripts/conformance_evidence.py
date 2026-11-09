"""Unified Syntra 1.0 implementation evidence, not a conformance declaration.

Examples (repo root, PyYAML from scripts/requirements-evidence.txt):
  python3 scripts/conformance_evidence.py --candidate-agreement offline
  python3 scripts/conformance_evidence.py --output /tmp/new-evidence --run-local corpus

The scoped upstream lock verifies exact consumed implementation inputs. Fixture
transcriptions and optional current candidate agreement are checked separately
from supplemental local execution. TCP, WS and WSS are carriers of one protocol.
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

from sdd_inputs import TEST_ASSETS, regular_file, verify_inputs
from upstream_snapshot import ROOT, REPOSITORY, REVISION, digest, git
from manifest_adapters import IMPLEMENTATION_WIRE_CONTRACT, SUPPLEMENTAL_SCENARIOS, execute_supplemental


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


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError(f"non-string or duplicate YAML key: {key!r}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_yaml(data):
    return yaml.load(data, Loader=UniqueSafeLoader)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_transcriptions(source, root=ROOT):
    """Check handwritten WS constants, NOT runtime behavior or cryptographic vectors."""
    origin = "conformance/test-vectors/websocket/fixtures.yaml"
    fixtures = {row["id"]: row for row in load_yaml(source[origin])["fixtures"]}
    prefix = fixtures["websocket/VEC-WS-009"]
    good = prefix["frame_hex"]
    suffix = re.search(r"Append ([0-9a-f]+) ", prefix["unknown_field_good"])
    if not suffix or len(bytes.fromhex(good)) >= 128:
        raise ValueError("review changed WS prefix/unknown-field fixture transcription")
    ping = fixtures["websocket/VEC-WS-005"]
    close = fixtures["websocket/VEC-WS-006"]
    expected = {
        "NO_LENGTH_PREFIX_GOOD_HEX": good,
        "UNKNOWN_FIELD_SUFFIX_HEX": suffix[1],
        "VARINT_PREFIXED_HEX": bytes([len(bytes.fromhex(good))]).hex() + good,
        "U32_PREFIXED_HEX": len(bytes.fromhex(good)).to_bytes(4, "big").hex() + good,
        "SUFFIXED_HEX": good + "00",
        "PING_WIRE_HEX": ping["server_wire_hex"], "PONG_WIRE_HEX": ping["client_wire_hex"],
        "CLOSE_CLIENT_WIRE_HEX": close["client_wire_hex"],
        "CLOSE_HOST_WIRE_HEX": close["server_wire_hex"],
    }
    name = "tests/interoperability/vectors.rs"
    text = regular_file(root, name).decode("utf-8")
    pairs = re.findall(r'pub const (\w+_HEX): &str = "([0-9a-f]+)";', text)
    if len(pairs) != len(dict(pairs)) or dict(pairs) != expected:
        raise ValueError("handwritten WS vector transcription drift")
    close_codes = fixtures["websocket/VEC-WS-007"]
    expected_codes = {row["code"] for row in close_codes["mapping"].values()}
    expected_codes.add(int(close["server_wire_hex"][-4:], 16))
    table = re.search(r"CLOSE_CODE_TABLE:.*?= &\[(.*?)\];", text, re.S)
    reserved = re.search(r"RESERVED_CLOSE_CODES:.*?= &\[(.*?)\];", text)
    if not table or {int(code) for code in re.findall(r"\((\d+),", table[1])} != expected_codes:
        raise ValueError("handwritten WS close-code transcription drift")
    never_wire = re.search(r"codes ([0-9, ]+) MUST", close_codes["asserts"][0])
    if not reserved or not never_wire or re.findall(r"\d+", reserved[1]) != re.findall(r"\d+", never_wire[1]):
        raise ValueError("handwritten WS reserved-code transcription drift")
    tcp_origin = "conformance/test-vectors/tcp/byte-vectors.yaml"
    maximum = load_yaml(source[tcp_origin])["default_max_frame_bytes"]
    bound = re.search(r"MAX_FRAME_BYTES: usize = ([0-9_]+);", text)
    if not bound or int(bound[1].replace("_", "")) != maximum:
        raise ValueError("handwritten envelope bound transcription drift")
    return {"kind": "fixture_transcription_only", "verdict": "PASS", "formal_conformance": False,
            "source": name, "source_sha256": digest(text.encode()),
            "origins": {origin: digest(source[origin]), tcp_origin: digest(source[tcp_origin])}}


def implementation_identity(root):
    names = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
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
        "head": git(root, "rev-parse", "HEAD").decode().strip(),
        "dirty": bool(git(root, "status", "--porcelain", "--untracked-files=all").strip()),
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
    if lane in NATIVE_LOCAL_LANES:
        test = NATIVE_LOCAL_LANES[lane]
        command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                   "--features", "tls-rustls,native-enrollment", "--lib", test]
    else:
        test = LOCAL_LANES[lane]
        command = ["cargo", "test", "--locked", "-p", "syntra-runtime", "--no-default-features",
                   "--test", "conformance_runner", test]
    command += ["--", "--exact", "--show-output", "--color", "never"]
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
    parser.add_argument("--upstream", type=Path, help="defaults to SYNTRA_SDD_ROOT or ../syntra")
    parser.add_argument("--run-local", action="append", choices=sorted(LOCAL_LANES.keys() | NATIVE_LOCAL_LANES.keys() | set(SUPPLEMENTAL_SCENARIOS)), default=[],
                        help="repeat supplemental local validation lanes")
    parser.add_argument("--candidate-agreement", choices=("offline", "worktree", "release"),
                        help="verify the current unified contract via protocol_contract; release verifies committed candidate blobs, not publication authorization")
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
    provenance, source = verify_inputs(ROOT, args.upstream)
    if source is None:
        raise ValueError("evidence requires exact committed implementation input blobs")
    candidate_agreement = None
    scope: dict = {"protocol": "Syntra 1.0"}
    if args.candidate_agreement:
        from protocol_contract import load_record, verify_candidate
        candidate_agreement = verify_candidate(ROOT, args.upstream, args.candidate_agreement)
        scope["carriers"] = sorted(load_record(ROOT)["contract"]["carriers"])
    transcriptions = verify_transcriptions(source)
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
        "format_version": 2, "kind": "implementation_evidence_not_conformance_declaration",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "formal_conformance_claimed": False,
        "candidate_agreement": candidate_agreement,
        "implementation_wire_contract": IMPLEMENTATION_WIRE_CONTRACT,
        "scope": scope,
        "pins": {"specification": {"repository": REPOSITORY, "commit": REVISION},
                 "implementation_inputs": {**provenance, "sha256": {
                     name: digest(data) for name, data in sorted(source.items())}},
                 "implementation_before": before,
                 "implementation_after": after, "python": platform.python_version(),
                 "pyyaml": yaml.__version__,
                 "test_asset_origins": TEST_ASSETS},
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
            "specification_freeze": "acceptance commit is not a freeze record",
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
