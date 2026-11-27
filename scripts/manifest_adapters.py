"""Local supplemental Syntra 1.0/WSS scenarios.

The Rust test emits observations; Python checks fresh execution identity,
stimuli, payloads, correlation and barriers. No CONF verdict is produced.
"""

import base64
from copy import deepcopy
import json
import os
import re
import secrets
import subprocess

from local_inputs import FIXTURES, ROOT, digest, read_json, regular_file
from local_yaml import load_yaml


CARRIER_ID = "SYNTRA-1.0-WSS"
contract = read_json(ROOT, 'protocol-contract.json')
IMPLEMENTATION_WIRE_CONTRACT = {"domain": contract['domain_ascii'], "ws_path": contract['websocket_endpoint'],
                                "subprotocol": contract['websocket_subprotocol']}


SCENARIO_FIXTURE = FIXTURES / 'wss-scenarios.yaml'
_scenario_source = regular_file(ROOT, SCENARIO_FIXTURE)
SCENARIO_FIXTURE_SHA256 = digest(_scenario_source)
SUPPLEMENTAL_SCENARIOS = load_yaml(_scenario_source)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def varint(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def uint(tag, value, bits=32):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"invalid fixture uint{bits}")
    return varint(tag << 3) + varint(value) if value else b""


def blob(tag, data):
    return varint((tag << 3) | 2) + varint(len(data)) + data


def frame_bytes(frame):
    """Narrow public fixture encoder, never an alternate production decoder."""
    if "raw_b64" in frame:
        if set(frame) != {"raw_b64"}:
            raise ValueError("ambiguous raw fixture")
        return base64.b64decode(frame["raw_b64"], validate=True)
    envelope = uint(1, 1) + uint(2, frame["request_id"], 64)
    if frame["body"] == "request":
        known = {"method", "payload_b64", "timeout_ms"}
        payload = base64.b64decode(frame["payload_b64"], validate=True)
        envelope += blob(12, blob(1, frame["method"].encode()) + blob(2, payload) + uint(3, frame.get("timeout_ms", 0)))
    elif frame["body"] == "hello":
        known = {"min_version", "max_version"}
        envelope += blob(10, uint(1, frame["min_version"]) + uint(2, frame["max_version"]))
    else:
        raise ValueError("fixture body not implemented")
    if set(frame) - known - {"request_id", "body", "unknown_fields"}:
        raise ValueError("fixture encoder lacks declared input fields")
    for field in frame.get("unknown_fields", []):
        if set(field) != {"number", "wire_type", "value_b64"} or (field["number"], field["wire_type"]) != (90, 2):
            raise ValueError("unreviewed unknown-field fixture")
        envelope += blob(90, base64.b64decode(field["value_b64"], validate=True))
    return envelope


def scenario_for(identifier):
    require(identifier in SUPPLEMENTAL_SCENARIOS, "unknown supplemental scenario")
    return deepcopy(SUPPLEMENTAL_SCENARIOS[identifier])


def verify_scenario_fixture(root, expected_sha256):
    source = regular_file(root, SCENARIO_FIXTURE)
    require(digest(source) == expected_sha256 == SCENARIO_FIXTURE_SHA256,
            "WSS scenario fixture digest differs from captured input")
    require(canonical(load_yaml(source)) == canonical(SUPPLEMENTAL_SCENARIOS),
            "captured WSS scenarios differ from fixture data")


def scenario_inputs(case):
    return {"scenario_sha256": digest(canonical(case)),
            "frames_hex": [frame_bytes(frame).hex() for frame in case["input"].get("frames", [])],
            "control_frames_hex": [frame_bytes(frame).hex() for frame in case.get("control_connection", {}).get("frames", [])]}


def request_for(identifier):
    case = scenario_for(identifier)
    for expected in [case["expected"], *([case["control_connection"]["expected"]] if "control_connection" in case else [])]:
        require(not (set(expected) - {"connection_state", "session_state", "frames", "error"}),
                "adapter lacks an oracle for declared expected fields")
        for frame in expected.get("frames", []):
            require(not (set(frame) - {"request_id", "body", "payload_b64", "shape", "note"}),
                    "adapter lacks an oracle for declared expected frame fields")
        require(not (set(expected.get("error", {})) - {"code", "message", "message_pattern", "observer", "carriage"}),
                "adapter lacks an oracle for declared error fields")
    return {"protocol": 2, "kind": "supplemental_local_scenario", "formal_conformance": False,
            "nonce": secrets.token_hex(24), "scenario_id": identifier,
            "fixture_sha256": SCENARIO_FIXTURE_SHA256, "role": "server",
            "carrier_id": CARRIER_ID, "scenario": case, **scenario_inputs(case)}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def expected_frames(expected, actual):
    require(len(expected) == len(actual), "response frame count mismatch")
    for want, got in zip(expected, actual):
        for key in ("request_id", "body", "shape"):
            if key in want:
                require(got.get(key) == want[key], f"response {key} mismatch")
        if "payload_b64" in want:
            require(got.get("payload_hex") == base64.b64decode(want["payload_b64"], validate=True).hex(), "response payload mismatch")
        if "payload_b64" in want or "shape" in want:
            require("error" not in got, "successful response also carries an error")


def expected_observation(want, got):
    for key in ("connection_state", "session_state"):
        require(got.get(key) == want[key], f"{key} mismatch")
    if "frames" in want:
        expected_frames(want["frames"], got["frames"])
    if "error" in want:
        if want["error"].get("carriage") == "local_only":
            error = got["error"]
        else:
            errors = [frame["error"] for frame in got["frames"] if "error" in frame]
            require(len(errors) == 1, "expected exactly one error observation")
            error = errors[0]
        for key in ("code", "message", "observer", "carriage"):
            if key in want["error"]:
                require(error.get(key) == want["error"][key], f"error {key} mismatch")
        pattern = want["error"].get("message_pattern", "")
        if pattern:
            require(pattern.startswith("NEGATIVE:"), "unimplemented message assertion")
            require(isinstance(error.get("message"), str), "missing wire diagnostic observation")
            require(pattern.removeprefix("NEGATIVE:").lower() not in error["message"].lower(), "forbidden diagnostic")


def validate_result(request, result, root=ROOT):
    verify_scenario_fixture(root, request["fixture_sha256"])
    case = scenario_for(request["scenario_id"])
    require(canonical(request["scenario"]) == canonical(case) and
            all(request[key] == value for key, value in scenario_inputs(case).items()),
            "request differs from captured scenario")
    for key in ("protocol", "kind", "formal_conformance", "nonce", "scenario_id", "scenario_sha256", "role", "carrier_id"):
        require(result.get(key) == request[key], f"stale/mismatched execution {key}")
    wss = contract['carriers'][CARRIER_ID]
    require(result.get("carrier") == {"tls":wss['tls_minimum'], "termination":wss['tls_termination'], "noise_mode":"bootstrap",
                                      "wire":"Syntra1.0/WSS", **IMPLEMENTATION_WIRE_CONTRACT}, "carrier execution proof missing")
    got = result["observation"]
    expected_observation(case["expected"], got)
    if "error" in case["expected"] and case["expected"]["error"].get("carriage", "wire") == "wire":
        require(len(got["frames"]) == 1, "wire error must be one correlated terminal result")
        terminal = got["frames"][0]
        require(terminal.get("body") == "result" and terminal.get("request_id") == case["input"]["frames"][0]["request_id"],
                "error terminal is not correlated to the supplemental invocation")
        require(terminal.get("error", {}).get("code") == case["expected"]["error"]["code"] and "payload_hex" not in terminal,
                "wire error is missing or also reports success")
    sent = got["sent_frames_hex"]
    start = 0 if request["scenario_id"] == "wss-ready" else 1  # encrypted hello is setup
    require(sent[start:start + len(request["frames_hex"])] == request["frames_hex"], "executed stimulus differs from supplemental input")
    checks = got["checks"]
    identifier = request["scenario_id"]
    if identifier != "wss-duplicate-id":
        require(checks.get("followup_usable_same_session") is True, "missing actual post-scenario usability exchange")
    if identifier == "wss-duplicate-id":
        require(checks == {"first_handler_started":True, "held_until_violation_and_closure":True,
                           "offending_dispatches":0, "peer_transport_closed":True, "peer_success_results":0}, "duplicate barrier/negative observations incomplete")
    elif identifier == "wss-reverse-completion":
        require(checks["all_admitted_before_release"] == 16 and checks["completed_before_release"] == 0,
                "all-admitted barrier not observed")
        require(checks["release_order"] == list(range(36,20,-1)), "reverse-completion ordering not observed")
    elif identifier == "wss-deadline":
        require(checks["handler_delay_ms"] == case["input"]["faults"]["handler_delay_ms"], "wrong handler delay fault")
        # Real host timer, not an injected error. Tolerance is declared here,
        # before measurement: 100ms request, 1000ms handler, 80..600ms receipt.
        require(80 <= checks["terminal_elapsed_ms"] <= 600, "deadline terminal outside declared fixture window")
        require(checks["completed_handlers_at_terminal"] == 0 and checks["dispatched_handlers"] == 1,
                "deadline did not race a genuinely delayed outstanding handler")
    elif identifier == "wss-payloads":
        require(len(sent) == 1 + len(request["frames_hex"]) + 1, "expected only setup, declared calls and followup")
    elif identifier == "wss-ready":
        require(checks["ready_without_optional_negotiation"] is True, "missing no-negotiation Ready observation")
    elif identifier == "wss-recovery-isolation":
        control = got["control_connection"]
        expected_observation(case["control_connection"]["expected"], control)
        require(control["sent_frames_hex"][1:] == request["control_frames_hex"], "control stimulus differs")
        n, s = [row["decoded"] for row in control["frames"]]
        require(n == {"profile_version":1,"selected_version":1,"max_subscriptions_per_connection":64,
                      "max_pending_rpcs_per_connection":16,"max_page_bytes":262144,"max_snapshot_pages":256}, "negotiated bounds mismatch")
        require(s["profile_version"] == 1 and s["generation"] == 7 and bool(s["subscription_handle_hex"])
                and s["catchup_boundary_hex"] == b"boundary-A".hex(), "invalid fresh subscription shape/boundary")
        for key in ("same_service_principal_scope_selector", "distinct_connections"):
            require(checks[key] is True, f"missing paired-control {key}")
        require(checks["unconfirmed_captures"] == 0 and checks["control_captures"] == 1, "unconfirmed handle/checkpoint allocation")
        require(checks["probe_after_control"]["error"]["code"] == "UNIMPLEMENTED", "confirmation leaked to probe connection")
    return got


def execute_supplemental(identifier, output, execution_proof, root=ROOT):
    """Fresh local process, bounded logs, no imported verdict trust."""
    request = request_for(identifier)
    row = {"lane": identifier, "kind": request["kind"], "formal_conformance": False,
           "fixture_sha256": request["fixture_sha256"], "scenario_sha256": request["scenario_sha256"], "carrier_id": CARRIER_ID}
    stem = "local-" + identifier
    request_path, result_path = output / (stem + ".request.json"), output / (stem + ".observed.json")
    log = output / (stem + ".log")
    for path in (request_path, result_path, log):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing existing supplemental artifact: {path.name}")
    with request_path.open("x", encoding="utf-8") as stream:
        json.dump(request, stream, indent=2)
    command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
               "--features", "tls-rustls,native-enrollment", "--test", "manifest_cases", "supplemental_scenario", "--",
               "--exact", "--ignored", "--show-output", "--color", "never"]
    execution = {"command":command, "RUSTUP_TOOLCHAIN":"1.89.0", "artifacts":{},
                 "scope":{"iut":"native host", "peer":"raw harness, not client IUT", "mode":"bootstrap",
                           "transport":"direct-host TLS 1.3/WSS + Syntra 1.0", "enrollment_lifecycle_claimed":False}}
    verdict, reason = "NOT_EXECUTED", "executor could not finish"
    try:
        with log.open("x", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT, timeout=180,
                                       env={**os.environ, "RUSTUP_TOOLCHAIN":"1.89.0",
                                             "SYNTRA_SUPPLEMENTAL_REQUEST":str(request_path.resolve()), "SYNTRA_SUPPLEMENTAL_RESULT":str(result_path.resolve())})
        execution["exit_code"] = completed.returncode
        proof, proof_reason = execution_proof(completed.returncode, log.read_text(), "supplemental_scenario")
        if proof != "PASS":
            # A compiler/tool failure is not a scenario behavior failure. Prove
            # that the exact test actually failed before attributing FAIL.
            text = log.read_text()
            failed_test = bool(re.search(r"^test supplemental_scenario \.\.\. FAILED$", text, re.M)
                               and re.search(r"test result: FAILED\. 0 passed; 1 failed; 0 ignored;", text))
            verdict = "FAIL" if failed_test else "NOT_EXECUTED"
            reason = "no complete supplemental execution: " + proof_reason
        elif not result_path.is_file() or result_path.is_symlink():
            verdict, reason = "FAIL", "executed test emitted no fresh observation artifact"
        else:
            result = json.loads(result_path.read_text())
            validate_result(request, result, root)
            verdict, reason = "PASS", "local supplemental stimuli and observations verified on Syntra 1.0/WSS; not formal conformance"
    except (OSError, subprocess.TimeoutExpired) as error:
        reason = f"executor unavailable/incomplete: {type(error).__name__}"
    except (ValueError, KeyError, TypeError) as error:
        verdict, reason = "FAIL", f"supplemental observation verification failed: {error}"
    for path in (request_path, result_path, log):
        if path.is_file() and not path.is_symlink():
            execution["artifacts"][path.name] = digest(path.read_bytes())
    row.update(verdict=verdict, reason=reason, executed=verdict in ("PASS", "FAIL"),
               execution=execution)
    return row
