"""Candidate agreement, separate from accepted-base provenance and release approval.

--record-worktree explicitly records four machine inputs, never SDD Markdown.
--offline checks local semantic copies and Rust only; it proves no external bytes.
--worktree reads exact external bytes and checks the recorded HEAD/branch/dirty bit.
--release requires a real committed candidate and verifies its Git blobs. A pin is
necessary for publication, not release authorization or a conformance verdict.

Record v2 separates raw source hashes from derived implementation artifacts.
Context IDs/base references are normalized by source array order; all other
fields (including mutation recipes and encoded bytes) are preserved. The local
JSON is serialized with indent=2, ensure_ascii=True and a final newline.
Upstream transport suite selectors project to CARRIER bindings of one protocol.
"""

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True

from candidate_rust import (BROWSER_FIXTURES, BROWSER_JS, BROWSER_WS, KERNEL, NATIVE_FIXTURES, NATIVE_WS,
                            binding_sources, browser_fixture_bounds, probe)
from sdd_inputs import regular_file, sdd_root
from upstream_snapshot import ROOT, REPOSITORY, REVISION, SCOPE, digest, git, read_lock

LOCK = "protocol-contract.json"
FIXTURE = "tests/interoperability/fixtures/syntra-1.0-context.json"
INPUTS = {
    "contract": "compatibility/syntra-1.0.json",
    "contexts": "conformance/test-vectors/connection/context-vectors.json",
    "vectors": "conformance/test-vectors/connection/context-vectors.yaml",
    "registry": "conformance/profiles.yaml",
}
CONTRACT_KEYS = ("format_version", "status", "protocol", "domain_ascii", "core_wire_version",
                 "protobuf_package", "websocket_endpoint", "websocket_subprotocol", "channel_limits",
                 "context_layout", "carriers")
REGISTRY_KEYS = ("id", "kind", "carrier", "binding", "domain", "endpoint", "subprotocol", "secure",
                  "production_allowed", "tls_minimum", "tls_termination")
CONTEXT_TRANSFORMATION = "syntra-context-identifiers-by-source-order-v1"
CARRIER_TRANSFORMATION = "transport-registry-to-carrier-bindings-v1"
NEGATIVE_MUTATIONS = frozenset((
    "unsupported-domain", "unsupported-format", "zero-mode", "unknown-carrier",
    "bootstrap-epoch", "returning-handle", "empty-scope", "oversize-scope",
    "truncated", "trailing", "invalid-utf8", "scope-byte-length",
))
RUST_INPUTS = (KERNEL, NATIVE_FIXTURES, BROWSER_FIXTURES, BROWSER_JS, NATIVE_WS, BROWSER_WS,
               "crates/syntra-core/src/handshake.rs", "crates/syntra-core/src/frame.rs",
               "proto/syntra/v1/envelope.proto", "scripts/manifest_adapters.py",
               "scripts/candidate_rust.py", "scripts/protocol_contract.py")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(content):
    def reject_constant(value):
        raise ValueError(f"non-JSON numeric constant: {value}")
    return json.loads(content, object_pairs_hook=unique, parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def fixture_bytes(contexts):
    return (json.dumps(contexts, indent=2, ensure_ascii=True) + "\n").encode()


def normalize_contexts(contexts):
    """Rename identifiers/references only; never reinterpret bytes or recipes."""
    result = copy.deepcopy(contexts)
    names = {}
    for index, row in enumerate(result["contexts"], 1):
        require(isinstance(row["id"], str) and row["id"] not in names, "duplicate/invalid source context ID")
        name = f"SYNTRA-CONTEXT-{index:02d}"
        names[row["id"]] = name
        row["id"] = name
    seen = set()
    for index, row in enumerate(result["negative_recipes"], 1):
        require(isinstance(row["id"], str) and row["id"] not in seen, "duplicate/invalid source negative ID")
        seen.add(row["id"])
        require(row["base"] in names, "negative recipe references missing source context")
        row.update(id=f"SYNTRA-N{index:02d}", base=names[row["base"]])
    return result


def accepted_base(root):
    entries = read_lock(root)
    return {"repository": REPOSITORY, "revision": REVISION, "scope": SCOPE,
            "lock_format_version": 2, "input_count": len(entries),
            "lock_sha256": digest(regular_file(root, "upstream.lock.json"))}


def fixture_provenance(source, content):
    return {"path": FIXTURE, "kind": "derived-context-fixture",
            "source_path": INPUTS["contexts"], "source_sha256": source["files"][INPUTS["contexts"]],
            "transformation": CONTEXT_TRANSFORMATION, "sha256": digest(content)}


def carrier_provenance(source, bindings):
    return {"source_path": INPUTS["registry"], "source_sha256": source["files"][INPUTS["registry"]],
            "transformation": CARRIER_TRANSFORMATION, "canonical_sha256": digest(canonical(bindings))}


def identity(upstream):
    require(not upstream.is_symlink(), "SDD root cannot be a symlink")
    return {"baseline_git_head": git(upstream, "rev-parse", "HEAD").decode().strip(),
            "branch": git(upstream, "branch", "--show-current").decode().strip(),
            "dirty": bool(git(upstream, "status", "--porcelain", "--untracked-files=all").strip())}


def source_documents(source):
    # Reuse the evidence tool's duplicate-key-safe YAML parser, not yaml.load.
    from conformance_evidence import load_yaml
    contract = parse_json(source[INPUTS["contract"]])
    contexts = parse_json(source[INPUTS["contexts"]])
    vectors = load_yaml(source[INPUTS["vectors"]])
    profiles = load_yaml(source[INPUTS["registry"]])
    projection = {key: contract[key] for key in CONTRACT_KEYS}
    require(contract["status"] == contexts["status"] == vectors["status"] == "candidate-sdd",
            "machine input is not explicitly candidate-sdd")
    require(contexts["domain_ascii"] == contract["domain_ascii"], "context domain disagrees with compatibility input")
    require(contexts["contexts"] == vectors["vectors"], "JSON/YAML context vectors disagree")
    keys = ("id", "base", "mutation", "expected")
    require([{key: row[key] for key in keys} for row in contexts["negative_recipes"]] == vectors["negative_recipes"],
            "JSON/YAML negative recipes disagree")
    registry = [{**{key: row[key] for key in REGISTRY_KEYS if key in row}, "kind": "CARRIER"}
                 for row in profiles["profiles"] if row["kind"] == "TRANSPORT_PROFILE"]
    require(set(vectors["profile"]) == set(contract["carriers"]), "context vectors select different carriers")
    require(profiles["core_wire_version"] == contract["core_wire_version"]
            and profiles["protobuf_package"] == contract["protobuf_package"], "registry core identity mismatch")
    check_registry(projection, registry)
    contexts = normalize_contexts(contexts)
    check_context_coverage(projection, contexts)
    return projection, contexts, registry


def check_registry(contract, registry):
    require(contract["format_version"] == "1.0" and contract["status"] == "candidate-sdd",
            "unsupported/non-candidate semantic contract")
    require(contract["protocol"] == "Syntra " + contract["domain_ascii"].removeprefix("syntra."),
            "protocol name/domain disagree")
    require(type(contract["core_wire_version"]) is int and contract["core_wire_version"] > 0,
            "core wire version must be an integer")
    require(all(type(value) is int and value > 0 for value in contract["channel_limits"].values()),
            "channel limits must be positive integers, not booleans")
    require(all(type(value) is int for row in contract["context_layout"].values()
                for value in (row if isinstance(row, list) else [row]) if value is not None),
            "layout coordinates must be integers")
    require(len(registry) == len(contract["carriers"]), "carrier registry is incomplete or has extra bindings")
    indexed = {row["id"]: row for row in registry}
    require(len(indexed) == len(registry) and set(indexed) == set(contract["carriers"]), "carrier registry IDs disagree")
    require({row["code"] for row in contract["carriers"].values()} == {1, 2, 3}, "unreviewed carrier codes")
    for name, want in contract["carriers"].items():
        row = indexed[name]
        require(type(want["code"]) is int and type(row["carrier"]) is int, "carrier code must be an integer")
        require(row["carrier"] == want["code"] and row["binding"] == want["binding"]
                and row["kind"] == "CARRIER"
                and row["production_allowed"] is want["production_allowed"]
                and row["domain"] == contract["domain_ascii"] and row["secure"] is True,
                f"carrier registry policy mismatch: {name}")
        if want["code"] in (2, 3):
            require(row["endpoint"] == contract["websocket_endpoint"]
                    and row["subprotocol"] == contract["websocket_subprotocol"], "registry WS constants disagree")
        if want["code"] == 2:
            require(want["production_allowed"] is False and want["scope"] == "loopback-development-only"
                    and want["binding"] == "websocket-h1-binary", "WS must stay restricted, not production")
        elif want["code"] == 3:
            require(want["production_allowed"] is True and row["tls_minimum"] == "1.3"
                    and row["tls_termination"] == "direct_host"
                    and want["binding"] == "websocket-h1-binary-verified-tls13", "WSS binding policy mismatch")
        else:
            require(want["production_allowed"] is True and want["binding"] == "tcp-u16be", "TCP binding policy mismatch")


def record_worktree(root=ROOT, upstream=None):
    upstream = sdd_root(upstream, root)
    before = identity(upstream)
    source = {name: regular_file(upstream, name) for name in INPUTS.values()}
    contract, contexts, registry = source_documents(source)
    after = identity(upstream)
    require(before == after and source == {name: regular_file(upstream, name) for name in INPUTS.values()},
            "SDD changed while recording; retry on a stable worktree")
    content = fixture_bytes(contexts)
    source_record = {"repository": REPOSITORY, **before, "candidate_revision": None,
                     "files": {name: digest(data) for name, data in source.items()}}
    record = {"format_version": 2, "kind": "worktree-not-release",
               "recorded_utc": datetime.now(timezone.utc).isoformat(),
               "accepted_base": accepted_base(root), "source": source_record,
               "contract": contract, "contract_sha256": digest(canonical(contract)), "carrier_bindings": registry,
               "carrier_bindings_provenance": carrier_provenance(source_record, registry),
               "context_fixture": fixture_provenance(source_record, content),
              "evidence_scope": "public encoding and source agreement only; not runtime CONF execution, review freeze or release authorization"}
    # Explicit generator, implementation-owned outputs only. No SDD file writes.
    require(not root.is_symlink(), "candidate root cannot be a symlink")
    for path in (LOCK, FIXTURE):
        target = root
        for part in Path(path).parts:
            target = target / part
            require(not target.is_symlink(), "candidate output cannot traverse a symlink")
    (root / FIXTURE).write_bytes(content)
    (root / LOCK).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return record


def load_record(root=ROOT):
    record = parse_json(regular_file(root, LOCK))
    require(type(record["format_version"]) is int and record["format_version"] == 2
            and record["kind"] in ("worktree-not-release", "committed-candidate"),
             "unknown candidate provenance kind")
    require(record["accepted_base"] == accepted_base(root), "accepted-base lock identity/digest changed")
    source = record["source"]
    require(source["repository"] == REPOSITORY and re.fullmatch(r"[0-9a-f]{40}", source["baseline_git_head"]),
            "candidate needs an actual full baseline Git HEAD")
    require(type(source["dirty"]) is bool and isinstance(source["branch"], str), "missing recorded worktree identity")
    require(set(source["files"]) == set(INPUTS.values()) and all(re.fullmatch(r"[0-9a-f]{64}", value)
            for value in source["files"].values()), "candidate machine-input inventory mismatch")
    content = regular_file(root, FIXTURE)
    require(record["context_fixture"] == fixture_provenance(source, content), "derived context fixture digest/provenance mismatch")
    contexts = parse_json(content)
    require(fixture_bytes(normalize_contexts(contexts)) == content, "local context fixture is not deterministically normalized")
    require(digest(canonical(record["contract"])) == record["contract_sha256"], "local semantic-contract digest mismatch")
    require(set(record["contract"]) == set(CONTRACT_KEYS), "candidate copy must be the reviewed semantic subset")
    if record["kind"] == "worktree-not-release":
        require(source["candidate_revision"] is None, "worktree baseline HEAD must not masquerade as a candidate commit")
    else:
        release_revision(record)  # Metadata consistency only; Git proof still needs --release.
    require(record["carrier_bindings_provenance"] == carrier_provenance(source, record["carrier_bindings"]),
            "derived carrier bindings digest/provenance mismatch")
    check_registry(record["contract"], record["carrier_bindings"])
    return record


def release_revision(record):
    revision = record["source"]["candidate_revision"]
    require(record["kind"] == "committed-candidate" and record["source"]["dirty"] is False
            and isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision)
            and revision != "0" * 40,
            "release pin blocked: candidate is worktree-not-release; commit the actual SDD bytes and record a verified committed candidate first")
    return revision


def record_commit(revision, root=ROOT, upstream=None):
    """Promote only when a real commit contains the already reviewed exact bytes.

    This does not commit, fetch, freeze the specification, or authorize a release.
    Preserve the dirty worktree observation as historical provenance.
    """
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "record a full real candidate commit, never HEAD/a branch")
    record = load_record(root)
    record["source"].setdefault("worktree_observation", {key: record["source"][key]
                                                         for key in ("baseline_git_head", "branch", "dirty")})
    record["kind"] = "committed-candidate"
    record["source"].update(candidate_revision=revision, dirty=False)
    external_source(record, sdd_root(upstream, root), "release")  # Prove Git objects before any write.
    record["recorded_utc"] = datetime.now(timezone.utc).isoformat()
    (root / LOCK).write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return record


def external_source(record, upstream, mode):
    if mode == "release":
        revision = release_revision(record)
        resolved = git(upstream, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
        require(resolved == revision, "candidate commit did not resolve exactly")
        git(upstream, "merge-base", "--is-ancestor", record["source"]["baseline_git_head"], revision)
        source = {}
        for name in INPUTS.values():
            tree = git(upstream, "ls-tree", revision, "--", name).decode()
            require(tree.startswith("100644 blob ") and tree.rstrip().endswith("\t" + name),
                    f"candidate commit input must be a regular nonexecutable blob: {name}")
            source[name] = git(upstream, "show", revision + ":" + name)
        observed = {"candidate_revision": revision, "kind": "exact_committed_git_blobs"}
    else:
        observed = identity(upstream)
        require(all(observed[key] == record["source"][key] for key in observed), "external HEAD/branch/dirty identity changed; explicit rerecord required")
        source = {name: regular_file(upstream, name) for name in INPUTS.values()}
        require(observed == identity(upstream), "external identity changed during verification")
    require({name: digest(data) for name, data in source.items()} == record["source"]["files"],
            "external machine-input byte drift; explicit rerecord/review required")
    contract, contexts, registry = source_documents(source)
    require(contract == record["contract"] and registry == record["carrier_bindings"], "external semantic projection drift")
    require(fixture_provenance(record["source"], fixture_bytes(contexts)) == record["context_fixture"],
            "external context transformation drift")
    if mode != "release":
        require(observed == identity(upstream) and source == {name: regular_file(upstream, name) for name in INPUTS.values()},
                "external machine inputs changed during verification")
    return contexts, observed


def check_context_coverage(contract, contexts):
    """Require reviewed attacks on each carrier, with semantically useful bases.

    Source order determines IDs, not coverage. Most recipes use bootstrap
    contexts; returning-handle requires returning state, and scope-byte-length
    uses a multibyte returning scope so byte/character counts actually differ.
    The same mutation on distinct bases is valid; repeating a case is not.
    """
    rows, negatives = contexts["contexts"], contexts["negative_recipes"]
    carriers = {row["code"] for row in contract["carriers"].values()}
    require(contexts["domain_ascii"] == contract["domain_ascii"], "local candidate domain mismatch")
    require(rows and all(isinstance(row.get("id"), str) and row["id"] for row in rows)
            and len({row["id"] for row in rows}) == len(rows), "empty/duplicate/incomplete context fixtures")
    require(all(type(row.get("mode")) is int and row["mode"] in (1, 2)
                and type(row.get("carrier")) is int and row["carrier"] in carriers for row in rows),
            "context fixtures contain unknown carrier/mode")
    require({(row["mode"], row["carrier"]) for row in rows} == {(mode, carrier) for mode in (1, 2) for carrier in carriers},
            "context fixtures must cover both modes on every carrier")
    indexed = {row["id"]: row for row in rows}
    ids, cases = set(), set()
    coverage = {carrier: set() for carrier in carriers}
    for row in negatives:
        require(isinstance(row.get("id"), str) and row["id"] and row["id"] not in ids,
                "negative fixture coverage: missing/duplicate recipe ID")
        ids.add(row["id"])
        require(row.get("mutation") in NEGATIVE_MUTATIONS and row.get("base") in indexed
                and row.get("expected") == "reject-before-noise",
                "negative fixture coverage: unknown mutation/base or bad expectation")
        case = (row["base"], row["mutation"])
        require(case not in cases, "negative fixture coverage: duplicate (base, mutation) case")
        cases.add(case)
        base, mutation = indexed[row["base"]], row["mutation"]
        mode = 2 if mutation in ("returning-handle", "scope-byte-length") else 1
        require(base["mode"] == mode, f"negative fixture coverage: {mutation} requires base mode {mode}")
        scope = base["scope"].encode("utf-8")
        if mutation == "scope-byte-length":
            require(len(scope) > len(base["scope"]),
                    "negative fixture coverage: scope-byte-length requires a multibyte scope")
        elif mutation == "invalid-utf8":
            require(len(scope) == 1, "negative fixture coverage: invalid-utf8 requires a single-byte scope")
        coverage[base["carrier"]].add(mutation)
    for carrier, mutations in coverage.items():
        require(mutations == NEGATIVE_MUTATIONS,
                f"negative fixture coverage missing on carrier {carrier}: {sorted(NEGATIVE_MUTATIONS - mutations)}")
    return [{"carrier": carrier, "mutations": sorted(coverage[carrier])} for carrier in sorted(carriers)]


def validate_rust(root, contract, contexts):
    rows, negatives = contexts["contexts"], contexts["negative_recipes"]
    coverage = check_context_coverage(contract, contexts)
    result = probe(root, rows, negatives, contract["context_layout"])
    metrics = [row for row in result if row["kind"] == "constants"]
    require(len(metrics) == 1, "no unambiguous Rust constant probe")
    got = metrics[0]
    limits, layout = contract["channel_limits"], contract["context_layout"]
    require(got["protocol"] == got["domain"] == contract["domain_ascii"] == contract["websocket_subprotocol"], "Rust PROTOCOL/DOMAIN/subprotocol mismatch")
    pairs = {"tag": "aead_tag_bytes", "ciphertext": "max_ciphertext_bytes", "plaintext": "max_plaintext_bytes",
             "frame": "max_serialized_frame_bytes", "records": "max_records_per_direction", "age": "max_age_seconds"}
    require(all(got[key] == limits[value] for key, value in pairs.items()), "Rust channel-limit mismatch")
    require(limits["authorization_key_bytes"] == got["auth_key"] == 32
            and got["noise"] == 32 + got["tag"], "key/Noise size mismatch")
    require(got["min_version"] == got["max_version"] == contract["core_wire_version"], "Rust core wire version mismatch")
    require(got["core_frame"] == limits["max_serialized_frame_bytes"], "Rust core frame bound mismatch")
    proto = regular_file(root, "proto/syntra/v1/envelope.proto").decode()
    require(re.search(r"(?m)^package " + re.escape(contract["protobuf_package"]) + r";", proto), "protobuf package mismatch")
    expected_layout = {"domain": [0, got["mode"]], "mode": [got["mode"], got["carrier"]],
        "carrier": [got["carrier"], got["key_id"]], "server_key_id": [got["key_id"], got["epoch"]],
        "epoch": [got["epoch"], got["handle"]], "handle": [got["handle"], got["scope_len"]],
        "scope_length_u16be": [got["scope_len"], got["scope"]], "scope": [got["scope"], None],
        "scope_bytes": [got["min_scope"], got["max_scope"]],
        "context_bytes": [got["scope"] + got["min_scope"], got["scope"] + got["max_scope"]],
        "m1_bytes": [got["min_m1"], got["max_m1"]], "m2_bytes": got["noise"]}
    require(layout == expected_layout, "Rust PROTOCOL-derived context layout/bounds mismatch")
    actual = {row["id"]: row["hex"] for row in result if row["kind"] == "context"}
    require(set(actual) == {row["id"] for row in rows}, "compiled context probe missing rows")
    for row in rows:
        encoded = bytes.fromhex(actual[row["id"]])
        require(actual[row["id"]] == row["context_hex"] == row["prologue_hex"]
                and len(encoded) == row["context_bytes"] and len(encoded) + got["noise"] == row["m1_bytes"],
                f"Rust/context fixture disagreement: {row['id']}")
    rejected = {row["id"]: row["rejected"] for row in result if row["kind"] == "negative"}
    require(set(rejected) == {row["id"] for row in negatives} and all(rejected.values()), "compiled Rust parser accepted a negative fixture")
    independent = [row for row in result if row["kind"] == "independent"]
    require(len(independent) >= 4 and len({row["id"] for row in independent}) == len(independent),
            "independent Rust fixture coverage is missing/duplicated")
    require(len({row["context_hex"] for row in independent}) == len(independent), "duplicate independent Rust context bytes")
    for row in independent:
        fields = set(row) - {"id", "kind"}
        require(any(row["id"] == want["id"] and all(row[key] == want[key] for key in fields) for want in rows),
                "independent Rust fixture disagrees with derived SDD context bytes/ID")
    browser = [row for row in result if row["kind"] == "browser_fixture"]
    require(len(browser) == 1 and any(row["carrier"] == 3 and row["context_hex"] == browser[0]["hex"] for row in rows),
            "independent browser context literal disagrees")
    from manifest_adapters import IMPLEMENTATION_WIRE_CONTRACT
    require(IMPLEMENTATION_WIRE_CONTRACT == {"domain": contract["domain_ascii"], "ws_path": contract["websocket_endpoint"],
                                            "subprotocol": contract["websocket_subprotocol"]}, "evidence candidate identity is stale")
    return {"kind": "compiled_source_encoding_agreement_not_full_crate_or_carrier_execution", "contexts": len(rows),
             "negative_parser_recipes": len(negatives), "negative_recipe_coverage": coverage,
             "independent_native_fixtures": len(independent),
            "independent_browser_literals": len(browser), "derived_constants": got,
            "bindings": binding_sources(root, contract), "browser_fixture_bounds": browser_fixture_bounds(root, contract)}


def verify_candidate(root=ROOT, upstream=None, mode="offline"):
    require(mode in ("offline", "worktree", "release"), "unknown candidate verification mode")
    record = load_record(root)
    require(mode != "worktree" or record["kind"] == "worktree-not-release",
            "--worktree verifies recorded uncommitted observations; use --release for committed Git-blob provenance")
    implementation = {name: digest(regular_file(root, name)) for name in (*RUST_INPUTS, LOCK, FIXTURE)}
    contexts = parse_json(regular_file(root, FIXTURE))
    external = None
    if mode != "offline":
        contexts, external = external_source(record, sdd_root(upstream, root), mode)
    agreement = validate_rust(root, record["contract"], contexts)
    require(implementation == {name: digest(regular_file(root, name)) for name in implementation},
            "Rust/candidate inputs changed during agreement check; rerun on a stable snapshot")
    return {"kind": "candidate_agreement_not_conformance_or_release_authorization", "verdict": "PASS",
            "mode": mode, "external_bytes_verified": mode != "offline", "external_identity": external,
             "recorded_provenance": record["source"], "provenance_kind": record["kind"],
             "derived_artifacts": {"context_fixture": record["context_fixture"],
                                   "carrier_bindings": record["carrier_bindings_provenance"],
                                   "external_transformations_verified": mode != "offline"},
            "implementation_input_sha256": implementation,
            "release_pin_verified": mode == "release", "publication_authorized": False,
             "accepted_base": record["accepted_base"], "accepted_base_unchanged": True, "agreement": agreement}


def run_rust_agreement(output, root=ROOT):
    """Supplemental exact regressions, never a CONF case mapping."""
    from conformance_evidence import local_verdict
    require(not output.exists() and not output.is_symlink(), "Rust agreement output must be a new directory")
    require(not output.resolve().is_relative_to(root.resolve()), "Rust agreement logs must be outside the worktree")
    output.mkdir(parents=False)
    lanes = [
        ("kernel-contexts", ["-p", "syntra-core", "--lib"], "secure_channel::context_tests::four_candidate_context_and_prologue_fixtures"),
        ("native-binding", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "wss"],
         "invalid_endpoints_and_carrier_mismatches_do_not_open_socket"),
        ("native-tls13", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "wss"],
         "wss_server_rejects_tls12_client_before_authentication"),
        ("loopback-ws", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "websocket"],
         "ws_rejects_non_loopback_and_secure_carrier"),
        ("browser-context", ["-p", "syntra-web", "--no-default-features", "--features", "browser-connection", "--test", "connection_records"],
         "browser_wss_context_uses_candidate_syntra_1_0_bytes"),
    ]
    results = []
    for lane, selector, test in lanes:
        command = ["cargo", "test", "--locked", *selector, test, "--", "--exact", "--show-output", "--color", "never"]
        path = output / (lane + ".log")
        try:
            with path.open("x") as log:
                completed = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT,
                    timeout=300, env={**os.environ, "RUSTUP_TOOLCHAIN": "1.88.0"})
            verdict, reason = local_verdict(completed.returncode, path.read_text(), test)
            status = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            verdict, reason, status = "NOT_EXECUTED", str(error), None
        results.append({"lane": lane, "command": command, "RUSTUP_TOOLCHAIN": "1.88.0", "test": test,
                        "verdict": verdict, "reason": reason, "exit_code": status, "formal_conformance": False,
                        "log": str(path), "log_sha256": digest(path.read_bytes()) if path.is_file() else None})
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--offline", action="store_true")
    modes.add_argument("--worktree", action="store_true")
    modes.add_argument("--release", action="store_true")
    modes.add_argument("--release-revision", action="store_true", help="print declared committed pin for fetching; --release must still verify its Git blobs")
    modes.add_argument("--record-worktree", action="store_true")
    modes.add_argument("--record-commit", metavar="FULL_SHA", help="verify real committed bytes before promoting the candidate record")
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--run-rust", action="store_true", help="run five exact supplemental agreement regressions")
    parser.add_argument("--output", type=Path, help="new external directory for exact Rust command logs")
    args = parser.parse_args()
    if args.offline and args.upstream:
        parser.error("--offline cannot verify --upstream; select --worktree explicitly")
    if args.run_rust and (not args.output or args.record_worktree or args.record_commit or args.release_revision):
        parser.error("--run-rust needs --output and a verification mode")
    if args.record_worktree:
        record = record_worktree(upstream=args.upstream)
        print(json.dumps({"recorded": LOCK, "kind": record["kind"], "source": record["source"]}, indent=2))
    elif args.record_commit:
        record = record_commit(args.record_commit, upstream=args.upstream)
        print(json.dumps({"recorded": LOCK, "kind": record["kind"], "source": record["source"]}, indent=2))
    elif args.release_revision:
        print(release_revision(load_record()))
    else:
        report = verify_candidate(upstream=args.upstream, mode="offline" if args.offline else "release" if args.release else "worktree")
        if args.run_rust:
            from conformance_evidence import implementation_identity
            before = implementation_identity(ROOT)
            report["supplemental_rust_agreement"] = run_rust_agreement(args.output)
            after = implementation_identity(ROOT)
            report["rust_execution_identity"] = {"before": {key: value for key, value in before.items() if key != "files"},
                                                  "after": {key: value for key, value in after.items() if key != "files"}}
            report["worktree_changed_during_rust_agreement"] = before != after
            if before != after:
                for row in report["supplemental_rust_agreement"]:
                    if row["verdict"] == "PASS":
                        row.update(verdict="NOT_EXECUTED", observed_test_verdict="PASS",
                                   reason="implementation changed during execution; retain observations and rerun")
            (args.output / "results.json").write_text(json.dumps(report["supplemental_rust_agreement"], indent=2) + "\n")
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        if any(row["verdict"] != "PASS" for row in report.get("supplemental_rust_agreement", [])):
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        sys.exit(f"Candidate contract check failed (not a conformance verdict): {error}")
