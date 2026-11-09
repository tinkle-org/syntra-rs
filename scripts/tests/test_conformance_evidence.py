"""Unified evidence scope, provenance, transcription and exact execution checks."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import conformance_evidence as evidence
import protocol_contract


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.source = {"proto/input.proto": b"exact source bytes"}
        self.provenance = {"upstream_files": 11, "provenance": "exact_committed_git_blobs"}
        self.identity = {"head": "pinned", "worktree_sha256": "snapshot", "files": {"input": "a"}}
        self.transcription = {"kind": "fixture_transcription_only", "verdict": "PASS",
                              "formal_conformance": False}

    def invoke(self, arguments=(), *, identities=None, local=()):
        with mock.patch.object(sys, "argv", ["conformance_evidence.py", *arguments]), \
                mock.patch.object(evidence, "verify_inputs", return_value=(self.provenance, self.source)) as verify, \
                mock.patch.object(evidence, "verify_transcriptions", return_value=self.transcription) as transcription, \
                mock.patch.object(evidence, "implementation_identity", side_effect=identities or [self.identity] * 2), \
                mock.patch.object(evidence, "run_local", side_effect=local) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = evidence.main()
        verify.assert_called_once_with(evidence.ROOT, None)
        transcription.assert_called_once_with(self.source)
        return status, json.loads(output.getvalue()), run

    def test_report_is_unified_implementation_evidence_with_no_formal_results(self):
        status, report, run = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(report["format_version"], 2)
        self.assertEqual(report["kind"], "implementation_evidence_not_conformance_declaration")
        self.assertEqual(report["scope"], {"protocol": "Syntra 1.0"})
        self.assertFalse(report["formal_conformance_claimed"])
        self.assertIsNone(report["candidate_agreement"])
        self.assertEqual(report["supplemental_results"], [])
        self.assertEqual(report["fixture_verification"], self.transcription)
        self.assertTrue(all(row["verdict"] == "NOT_EXECUTED" for row in report["external_gates"].values()))
        self.assertIn("formal_conformance", report["external_gates"])
        for removed in ("formal_summary", "results", "suite_schema_issues", "contract_alignment"):
            self.assertNotIn(removed, report)
        self.assertEqual(report["pins"]["implementation_before"], self.identity)
        self.assertEqual(report["pins"]["implementation_after"], self.identity)
        self.assertEqual(report["pins"]["implementation_inputs"], {
            **self.provenance, "sha256": {name: evidence.digest(data) for name, data in self.source.items()}})
        run.assert_not_called()

    def test_report_gates_cover_sdk_validation_scope(self):
        """Report only the remaining protocol, platform and review limits."""
        status, report, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(set(report["external_gates"]), {
            "formal_conformance", "physical_ios_android", "browser",
            "direct_host_tls13_wss", "independent_noise_vectors",
            "device_budgets_and_soak", "independent_security_review",
            "specification_freeze",
        })

    def test_current_candidate_verification_adds_only_current_contract_carriers(self):
        agreement = {"verdict": "PASS", "kind": "encoding_agreement", "publication_authorized": False}
        carriers = {"SYNTRA-1.0-TCP": {}, "SYNTRA-1.0-WS": {}, "SYNTRA-1.0-WSS": {}}
        for mode in ("offline", "worktree", "release"):
            with self.subTest(mode=mode), \
                    mock.patch.object(protocol_contract, "verify_candidate", return_value=agreement) as verify, \
                    mock.patch.object(protocol_contract, "load_record", return_value={"contract": {"carriers": carriers}}):
                status, report, _ = self.invoke(["--candidate-agreement", mode])
            verify.assert_called_once_with(evidence.ROOT, None, mode)
            self.assertEqual(status, 0)
            self.assertEqual(report["candidate_agreement"], agreement)
            self.assertEqual(report["scope"], {"protocol": "Syntra 1.0", "carriers": sorted(carriers)})
            self.assertFalse(report["formal_conformance_claimed"])
            self.assertEqual(report["external_gates"]["formal_conformance"]["verdict"], "NOT_EXECUTED")

    def test_supplemental_success_keeps_formal_gate_unexecuted_and_deduplicates_lanes(self):
        supplemental = {"kind": "supplemental_local_scenario", "lane": "wss-envelope",
                        "carrier_id": "SYNTRA-1.0-WSS", "formal_conformance": False, "verdict": "PASS"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            status, summary, run = self.invoke([
                "--run-local", "wss-envelope", "--run-local", "wss-envelope", "--output", str(output)],
                local=[supplemental])
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(sorted(path.name for path in output.iterdir()), ["report.json"])
        self.assertEqual(status, 0)
        run.assert_called_once_with("wss-envelope", output)
        self.assertEqual(report["supplemental_results"], [supplemental])
        self.assertEqual(summary["kind"], report["kind"])
        self.assertFalse(summary["formal_conformance_claimed"])
        self.assertEqual(report["external_gates"]["formal_conformance"]["verdict"], "NOT_EXECUTED")

    def test_failed_or_incomplete_requested_lanes_fail_the_command(self):
        for verdict in ("FAIL", "SKIP", "NOT_EXECUTED"):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as directory:
                status, _, _ = self.invoke(["--run-local", "corpus", "--output", str(Path(directory) / "evidence")],
                    local=[{"verdict": verdict, "formal_conformance": False}])
            self.assertEqual(status, 1)

    def test_worktree_drift_is_reported_even_without_local_commands(self):
        changed = {**self.identity, "files": {"input": "b", "new": "c"}}
        status, report, _ = self.invoke(identities=[self.identity, changed])
        self.assertEqual(status, 1)
        self.assertTrue(report["worktree_changed_during_run"])
        self.assertEqual(report["worktree_changed_files"], ["input", "new"])

    def test_supplemental_pass_is_withdrawn_if_worktree_changes(self):
        changed = {**self.identity, "head": "changed"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            status, _, _ = self.invoke(["--run-local", "wss-envelope", "--output", str(output)],
                identities=[self.identity, changed], local=[{"verdict": "PASS", "formal_conformance": False}])
            report = json.loads((output / "report.json").read_text())
        self.assertEqual(status, 1)
        self.assertEqual(report["supplemental_results"][0]["verdict"], "NOT_EXECUTED")

    def test_input_or_candidate_verification_failure_creates_no_artifacts(self):
        for target in ("verify_inputs", "verify_transcriptions", "candidate"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "evidence"
                owner, name = (protocol_contract, "verify_candidate") if target == "candidate" else (evidence, target)
                arguments = ["conformance_evidence.py", "--output", str(output)]
                if target == "candidate":
                    arguments += ["--candidate-agreement", "offline"]
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(evidence, "implementation_identity", return_value=self.identity), \
                        mock.patch.object(evidence, "verify_inputs", return_value=(self.provenance, self.source)), \
                        mock.patch.object(owner, name, side_effect=ValueError("input drift")), \
                        mock.patch.object(evidence, "run_local") as run:
                    with self.assertRaisesRegex(ValueError, "input drift"):
                        evidence.main()
                self.assertFalse(output.exists())
                run.assert_not_called()

    def test_release_candidate_failure_never_falls_back_to_offline_or_runs_lanes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            arguments = ["conformance_evidence.py", "--candidate-agreement", "release",
                         "--run-local", "corpus", "--output", str(output)]
            with mock.patch.object(sys, "argv", arguments), \
                    mock.patch.object(evidence, "implementation_identity", return_value=self.identity), \
                    mock.patch.object(evidence, "verify_inputs", return_value=(self.provenance, self.source)), \
                    mock.patch.object(protocol_contract, "verify_candidate", side_effect=ValueError("release pin blocked")) as verify, \
                    mock.patch.object(evidence, "run_local") as run:
                with self.assertRaisesRegex(ValueError, "release pin blocked"):
                    evidence.main()
            verify.assert_called_once_with(evidence.ROOT, None, "release")
            self.assertFalse(output.exists())
            run.assert_not_called()


class CliTests(unittest.TestCase):
    def test_removed_selectors_are_rejected_before_reads_or_writes(self):
        for selector in ("--profile", "--capability", "--case", "--unsupported-profile", "--role",
                         "--require-complete", "--execute"):
            with self.subTest(selector=selector), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "evidence"
                arguments = ["conformance_evidence.py", "--output", str(output), selector]
                if selector not in ("--require-complete", "--execute"):
                    arguments.append("invalid-token")
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.object(evidence, "verify_inputs") as verify, \
                        mock.patch.object(evidence, "implementation_identity") as identity, \
                        mock.patch.object(evidence, "run_local") as run, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    with self.assertRaises(SystemExit) as error:
                        evidence.main()
                self.assertEqual(error.exception.code, 2)
                self.assertIn("unrecognized arguments", stderr.getvalue())
                verify.assert_not_called()
                identity.assert_not_called()
                run.assert_not_called()
                self.assertFalse(output.exists())

    def test_local_execution_requires_output_before_reading_inputs(self):
        with mock.patch.object(sys, "argv", ["conformance_evidence.py", "--run-local", "corpus"]), \
                mock.patch.object(evidence, "verify_inputs") as verify, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                evidence.main()
        self.assertEqual(error.exception.code, 2)
        verify.assert_not_called()

    def test_existing_symlink_or_worktree_outputs_are_refused_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing"
            existing.mkdir()
            sentinel = existing / "report.json"
            sentinel.write_text("original")
            link = Path(directory) / "link"
            link.symlink_to(Path(directory) / "missing", target_is_directory=True)
            for output in (existing, link, evidence.ROOT / "invalid-evidence-output"):
                with self.subTest(output=output), \
                        mock.patch.object(sys, "argv", ["conformance_evidence.py", "--output", str(output)]), \
                        mock.patch.object(evidence, "verify_inputs") as verify:
                    with self.assertRaises(ValueError):
                        evidence.main()
                verify.assert_not_called()
            self.assertEqual(sentinel.read_text(), "original")
            self.assertTrue(link.is_symlink())
            self.assertFalse((evidence.ROOT / "invalid-evidence-output").exists())


class ExecutionProofTests(unittest.TestCase):
    def test_zero_selected_tests_is_not_pass(self):
        status, _ = evidence.local_verdict(0, "test result: ok. 0 passed; 0 failed; 0 ignored;", "test_name")
        self.assertEqual(status, "NOT_EXECUTED")

    def test_ignored_is_skip_not_pass(self):
        status, _ = evidence.local_verdict(0, "test result: ok. 0 passed; 0 failed; 1 ignored;", "test_name")
        self.assertEqual(status, "SKIP")

    def test_exit_zero_without_exact_named_test_is_not_pass(self):
        for text in ["", "test wrong_test ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;",
                     "test test_name ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored;",
                     "test test_name ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
                     "test result: ok. 0 passed; 0 failed; 0 ignored;"]:
            self.assertEqual(evidence.local_verdict(0, text, "test_name")[0], "NOT_EXECUTED")

    def test_only_exact_single_test_with_zero_exit_passes_supplemental_lane(self):
        text = "test test_name ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
        self.assertEqual(evidence.local_verdict(0, text, "test_name")[0], "PASS")
        self.assertEqual(evidence.local_verdict(101, text, "test_name")[0], "FAIL")

    def test_subprocess_is_exact_locked_and_preserves_log(self):
        for lane, name in evidence.LOCAL_LANES.items():
            def run(command, **kwargs):
                for arg in ("--exact", "--locked", "--no-default-features", "syntra-runtime", name):
                    self.assertIn(arg, command)
                self.assertEqual(kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.89.0")
                kwargs["stdout"].write(f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;")
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(evidence.subprocess, "run", side_effect=run):
                row = evidence.run_local(lane, Path(directory))
                self.assertEqual(row["verdict"], "PASS")
                self.assertFalse(row["formal_conformance"])
                self.assertEqual(row["artifact_sha256"], evidence.digest((Path(directory) / row["artifact"]).read_bytes()))

    def test_missing_tool_or_timeout_never_passes(self):
        for error in [FileNotFoundError(), subprocess.TimeoutExpired(["cargo"], 300)]:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(evidence.subprocess, "run", side_effect=error):
                self.assertEqual(evidence.run_local("corpus", Path(directory))["verdict"], "NOT_EXECUTED")


class ParserTests(unittest.TestCase):
    def test_duplicate_or_non_string_yaml_keys_are_rejected(self):
        for text in ("verdict: FAIL\nverdict: PASS\n", "1: invalid\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                evidence.load_yaml(text)

    def test_arbitrary_yaml_python_tags_are_rejected(self):
        with self.assertRaises(evidence.yaml.YAMLError):
            evidence.load_yaml("!!python/object/apply:os.system ['false']")


class TranscriptionTests(unittest.TestCase):
    def setUp(self):
        # Only the two source blobs actually consumed by the transcription check.
        self.source = {
            "conformance/test-vectors/websocket/fixtures.yaml": b"fixtures:\n"
            b"- {id: websocket/VEC-WS-009, frame_hex: '0801520408011001', unknown_field_good: 'Append d2050178 (unknown)'}\n"
            b"- {id: websocket/VEC-WS-005, server_wire_hex: '890670696e672d31', client_wire_hex: '8a8637fa213d47934f5a1acb'}\n"
            b"- {id: websocket/VEC-WS-006, client_wire_hex: '888237fa213d3412', server_wire_hex: '880203e8'}\n"
            b"- id: websocket/VEC-WS-007\n  mapping:\n"
            b"    a: {code: 1001}\n    b: {code: 1002}\n    c: {code: 1003}\n"
            b"    d: {code: 1007}\n    e: {code: 1008}\n    f: {code: 1009}\n    g: {code: 1011}\n"
            b"  asserts: ['codes 1005, 1006, 1015 MUST NEVER appear']\n",
            "conformance/test-vectors/tcp/byte-vectors.yaml": b"default_max_frame_bytes: 1048576\n",
        }

    def test_handwritten_constants_match_origins_but_do_not_claim_execution(self):
        result = evidence.verify_transcriptions(self.source)
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["formal_conformance"])
        self.assertEqual(result["origins"], {name: evidence.digest(data) for name, data in self.source.items()})

    def test_changed_origins_do_not_silently_keep_transcribed_constants(self):
        for origin, old, new in (
            ("conformance/test-vectors/websocket/fixtures.yaml", b"890670696e672d31", b"8900"),
            ("conformance/test-vectors/tcp/byte-vectors.yaml", b"1048576", b"2048"),
        ):
            source = {**self.source, origin: self.source[origin].replace(old, new)}
            with self.subTest(origin=origin), self.assertRaisesRegex(ValueError, "transcription drift"):
                evidence.verify_transcriptions(source)


if __name__ == "__main__":
    unittest.main()
