"""Local supplemental Syntra 1.0/WSS scenarios, never upstream case executors.

Inputs and assertions are owned here, independently of upstream fixtures.
The Rust test emits observations; Python checks fresh execution identity,
stimuli, payloads, correlation and barriers. No CONF verdict is produced.
"""

import base64
import json
import os
import re
import secrets
import subprocess

from upstream_snapshot import ROOT, digest


IMPLEMENTATION_WIRE_CONTRACT = {
    "domain": "syntra.1.0", "ws_path": "/syntra/1.0/ws", "subprotocol": "syntra.1.0",
}


CARRIER_ID = "SYNTRA-1.0-WSS"
SUPPLEMENTAL_SCENARIOS = (
    "wss-envelope", "wss-unknown-field", "wss-ready", "wss-reserved-method",
    "wss-payloads", "wss-duplicate-id", "wss-deadline", "wss-internal-error",
    "wss-reverse-completion", "wss-recovery-isolation",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def varint(value):
    if not isinstance(value, int) or value < 0 or value > (1 << 64) - 1:
        raise ValueError("invalid fixture varint")
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def uint(tag, value):
    return varint(tag << 3) + varint(value) if value else b""


def blob(tag, value):
    return varint((tag << 3) | 2) + varint(len(value)) + value


def frame_bytes(frame):
    """Narrow public fixture encoder, never an alternate production decoder."""
    if "raw_b64" in frame:
        if set(frame) != {"raw_b64"}:
            raise ValueError("ambiguous raw fixture")
        return base64.b64decode(frame["raw_b64"], validate=True)
    known = {"request_id", "body", "method", "payload_b64", "timeout_ms", "unknown_fields", "min_version", "max_version"}
    if set(frame) - known:
        raise ValueError("fixture encoder lacks declared input fields")
    encoded = uint(1, 1) + uint(2, frame["request_id"])
    if frame["body"] == "request":
        payload = base64.b64decode(frame["payload_b64"], validate=True)
        encoded += blob(12, blob(1, frame["method"].encode()) + blob(2, payload) + uint(3, frame.get("timeout_ms", 0)))
    elif frame["body"] == "hello":
        encoded += blob(10, uint(1, frame["min_version"]) + uint(2, frame["max_version"]))
    else:
        raise ValueError("fixture body not implemented")
    for field in frame.get("unknown_fields", []):
        if field["wire_type"] != 2 or field["number"] != 90:
            raise ValueError("unreviewed unknown-field fixture")
        encoded += blob(90, base64.b64decode(field["value_b64"], validate=True))
    return encoded


def scenario_for(identifier):
    """Local regression inputs, not transcriptions or renamed upstream cases."""
    require(identifier in SUPPLEMENTAL_SCENARIOS, "unknown supplemental scenario")

    def rpc(request_id=7, payload=b"hi", method="/example.Echo/Echo", timeout=500):
        return {"request_id": request_id, "body": "request", "method": method,
                "payload_b64": base64.b64encode(payload).decode(), "timeout_ms": timeout}

    def result(frame):
        return {"request_id": frame["request_id"], "body": "result", "payload_b64": frame["payload_b64"]}

    frames = [rpc()]
    expected: dict = {"connection_state": "ACTIVE", "session_state": "unchanged"}
    case = {"input": {"frames": frames}, "expected": expected}
    if identifier == "wss-unknown-field":
        frames[0]["unknown_fields"] = [{"number": 90, "wire_type": 2, "value_b64": "eA=="}]
    elif identifier == "wss-ready":
        frames[:] = [{"request_id": 0, "body": "hello", "min_version": 1, "max_version": 1}]
        expected.update(session_state="active", frames=[])
    elif identifier == "wss-duplicate-id":
        frames[:] = [rpc(payload=b"held-first"), rpc(payload=b"offending-second")]
        expected.update(connection_state="CLOSED", session_state="terminated_abnormally", frames=[],
                        error={"code": "FAILED_PRECONDITION", "observer": "detecting_host", "carriage": "local_only"})
    elif identifier == "wss-deadline":
        frames[:] = [rpc(9, timeout=100)]
        case["input"]["faults"] = {"handler_delay_ms": 1000}
        expected["error"] = {"code": "DEADLINE_EXCEEDED"}
    elif identifier == "wss-internal-error":
        expected["error"] = {"code": "INTERNAL", "message_pattern": "NEGATIVE:private-detail"}
    elif identifier == "wss-reverse-completion":
        frames[:] = [rpc(i, bytes([i]), timeout=5000) for i in range(21, 37)]
        expected["frames"] = [result(frame) for frame in reversed(frames)]
    elif identifier == "wss-reserved-method":
        frames[0]["method"] = "/syntra.v1.UpdateRecovery/Future"
        expected["error"] = {"code": "UNIMPLEMENTED"}
    elif identifier == "wss-recovery-isolation":
        subscribe = uint(1, 1) + blob(2, b"subscription-a")
        negotiate = uint(1, 1) + uint(2, 1) + uint(3, 1) + blob(4, b"syntra.update-recovery/1")
        frames[:] = [rpc(3, subscribe, "/syntra.v1.UpdateRecovery/Subscribe")]
        expected["error"] = {"code": "UNIMPLEMENTED"}
        case["control_connection"] = {
            "frames": [rpc(1, negotiate, "/syntra.v1.UpdateRecovery/Negotiate"), frames[0]],
            "expected": {"connection_state": "ACTIVE", "session_state": "unchanged", "frames": [
                {"request_id": 1, "body": "result", "shape": "RecoveryNegotiateResponse"},
                {"request_id": 3, "body": "result", "shape": "RecoverySubscribeResponse"}]}}
    if "frames" not in expected and "error" not in expected:
        expected["frames"] = [result(frame) for frame in frames]
    return case


def request_for(identifier):
    case = scenario_for(identifier)
    for expected in [case["expected"], *([case["control_connection"]["expected"]] if "control_connection" in case else [])]:
        require(not (set(expected) - {"connection_state", "session_state", "frames", "error"}),
                "adapter lacks an oracle for declared expected fields")
        for frame in expected.get("frames", []):
            require(not (set(frame) - {"request_id", "body", "payload_b64", "shape", "note"}),
                    "adapter lacks an oracle for declared expected frame fields")
        require(not (set(expected.get("error", {})) - {"code", "message_pattern", "observer", "carriage"}),
                "adapter lacks an oracle for declared error fields")
    return {"protocol": 2, "kind": "supplemental_local_scenario", "formal_conformance": False,
            "nonce": secrets.token_hex(24), "scenario_id": identifier,
            "scenario_sha256": digest(canonical(case)), "role": "server",
            "carrier_id": CARRIER_ID, "scenario": case,
            "frames_hex": [frame_bytes(frame).hex() for frame in case["input"].get("frames", [])],
            "control_frames_hex": [frame_bytes(frame).hex() for frame in case.get("control_connection", {}).get("frames", [])]}


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
        error = got.get("error")
        if error is None:
            errors = [frame["error"] for frame in got["frames"] if "error" in frame]
            require(len(errors) == 1, "expected exactly one error observation")
            error = errors[0]
        for key in ("code", "observer", "carriage"):
            if key in want["error"]:
                require(error.get(key) == want["error"][key], f"error {key} mismatch")
        pattern = want["error"].get("message_pattern", "")
        if pattern:
            require(pattern.startswith("NEGATIVE:"), "unimplemented message assertion")
            require(pattern.removeprefix("NEGATIVE:").lower() not in error.get("message", "").lower(), "forbidden diagnostic")


def validate_result(request, result):
    for key in ("protocol", "kind", "formal_conformance", "nonce", "scenario_id", "scenario_sha256", "role", "carrier_id"):
        require(result.get(key) == request[key], f"stale/mismatched execution {key}")
    require(result.get("carrier") == {"tls":"1.3", "termination":"direct_host", "noise_mode":"bootstrap",
                                      "wire":"Syntra1.0/WSS", **IMPLEMENTATION_WIRE_CONTRACT}, "carrier execution proof missing")
    got = result["observation"]
    case = request["scenario"]
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
        require([row["payload_hex"] for row in checks["payload_variants"]] == ["", "000102ffff"], "missing empty/non-UTF8 subcases")
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
           "scenario_sha256": request["scenario_sha256"], "carrier_id": CARRIER_ID}
    stem = "local-" + identifier
    request_path, result_path = output / (stem + ".request.json"), output / (stem + ".observed.json")
    log = output / (stem + ".log")
    for path in (request_path, result_path, log):
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing existing supplemental artifact: {path.name}")
    with request_path.open("x", encoding="utf-8") as stream:
        json.dump(request, stream, indent=2)
    command = ["cargo", "test", "--locked", "-p", "syntra-transport", "--no-default-features",
               "--features", "websocket,native-enrollment", "--test", "manifest_cases", "supplemental_scenario", "--",
               "--exact", "--ignored", "--show-output", "--color", "never"]
    execution = {"command":command, "RUSTUP_TOOLCHAIN":"1.88.0", "artifacts":{},
                 "scope":{"iut":"native host", "peer":"raw harness, not client IUT", "mode":"bootstrap",
                           "transport":"direct-host TLS 1.3/WSS + Syntra 1.0", "enrollment_lifecycle_claimed":False}}
    verdict, reason = "NOT_EXECUTED", "executor could not finish"
    try:
        with log.open("x", encoding="utf-8") as stream:
            completed = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT, timeout=180,
                                       env={**os.environ, "RUSTUP_TOOLCHAIN":"1.88.0",
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
            validate_result(request, result)
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
