"""CI evidence and native validation must not weaken required validation gates."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
NATIVE_COMMANDS = (
    "cargo test --locked",
    "cargo test --locked --workspace",
    "cargo test --locked -p syntra-net --no-default-features --features http",
    "cargo test --locked -p syntra-net --no-default-features --features managed,http,proxy --test http_connections --test network_http --test routes",
    "cargo test --locked -p syntra-net --no-default-features --features managed,websocket,proxy --test network_websocket --test routes",
    "cargo test --locked -p syntra-net --no-default-features --features managed,proxy,tls-rustls,native-enrollment,http",
    "cargo test --locked -p syntra-runtime --no-default-features --features file-store",
    "cargo test --locked -p syntra-ffi --no-default-features --features production",
    "cargo test --locked -p syntra-ffi --no-default-features --features test-fixture",
)


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Load CI and scheduled workflows for validation gate assertions."""
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        cls.scheduled = yaml.load(
            (ROOT / ".github/workflows/scheduled.yml").read_text(), Loader=yaml.BaseLoader)
        cls.steps = cls.workflow["jobs"]["rust"]["steps"]

    def test_pr_and_main_run_the_same_required_native_checks(self):
        """Keep workspace tests and exact-execution contracts blocking on PRs and main."""
        events = self.workflow["on"]
        self.assertIn("pull_request", events)
        self.assertFalse(events["pull_request"])
        self.assertEqual(events["push"], {"branches": ["main"]})
        for job_id in ("rust", "native-macos"):
            with self.subTest(job=job_id):
                job = self.workflow["jobs"][job_id]
                self.assertNotIn("if", job)
                self.assertNotIn("continue-on-error", job)
                self.assertIn(job_id, self.workflow["jobs"]["required"]["needs"])
                workspace, = [step for step in job["steps"]
                              if step.get("run") == "cargo test --locked --workspace"]
                self.assertNotIn("if", workspace)
                self.assertNotIn("continue-on-error", workspace)
        contract, = [step for step in self.steps
                     if step.get("run") == "python3 crates/syntra-net/tests/target_contract.py"]
        self.assertNotIn("if", contract)
        self.assertNotIn("continue-on-error", contract)

    def test_candidate_upload_follows_its_identified_producer(self):
        producer, = [step for step in self.steps if "--run-rust" in step.get("run", "")]
        upload, = [step for step in self.steps
                   if step.get("with", {}).get("name") == "candidate-rust-agreement"]
        self.assertEqual(producer.get("id"), "candidate_agreement")
        self.assertLess(self.steps.index(producer), self.steps.index(upload))
        self.assertIn('--output "$RUNNER_TEMP/candidate-rust-agreement"', producer["run"])
        self.assertEqual(upload["with"]["path"], "${{ runner.temp }}/candidate-rust-agreement")

    def test_candidate_upload_requires_execution_but_preserves_failure_evidence(self):
        upload, = [step for step in self.steps
                   if step.get("with", {}).get("name") == "candidate-rust-agreement"]
        # An earlier test failure skips the producer; success and failure both
        # attempt evidence preservation, but skipped/absent/cancelled do not.
        self.assertEqual(
            upload["if"],
            "${{ !cancelled() && (steps.candidate_agreement.outcome == 'success' || "
            "steps.candidate_agreement.outcome == 'failure') }}")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_candidate_validation_and_rust_job_remain_required(self):
        producer, = [step for step in self.steps if "--run-rust" in step.get("run", "")]
        self.assertNotIn("if", producer)
        self.assertNotIn("continue-on-error", producer)
        self.assertIn("--offline", producer["run"])
        self.assertIn("rust", self.workflow["jobs"]["required"]["needs"])
        self.assertNotIn("continue-on-error", self.workflow["jobs"]["rust"])

    def test_native_commands_are_identical_ordered_and_individually_blocking(self):
        """Require identical ordered native commands with no optional jobs or steps."""
        for workflow, job_id in ((self.workflow, "native-macos"),
                                 (self.scheduled, "compat-macos"),
                                 (self.scheduled, "compat-windows")):
            with self.subTest(job=job_id):
                job = workflow["jobs"][job_id]
                self.assertNotIn("if", job)
                self.assertNotIn("continue-on-error", job)
                runs = [step for step in job["steps"] if "run" in step]
                self.assertEqual([step["run"].strip() for step in runs], list(NATIVE_COMMANDS))
                self.assertEqual(len({step["name"] for step in runs}), 9)
                for step in job["steps"]:
                    self.assertNotIn("if", step)
                    self.assertNotIn("continue-on-error", step)
                for step in runs:
                    self.assertTrue(step["name"])
                    self.assertEqual(len(step["run"].strip().splitlines()), 1)
                    if job_id == "compat-windows":
                        self.assertEqual(step["shell"], "pwsh")

    def test_macos_ci_job_uses_pinned_actions_and_minimal_permissions(self):
        """Check the macOS runner, timeout, permissions, and pinned actions and toolchain."""
        job = self.workflow["jobs"]["native-macos"]
        self.assertEqual(job["runs-on"], "macos-15")
        self.assertEqual(job["timeout-minutes"], "45")
        self.assertEqual(job["permissions"], {"contents": "read"})
        actions = [step for step in job["steps"] if "uses" in step]
        self.assertEqual([step["uses"] for step in actions],
                         [step["uses"] for step in self.steps[:2]])
        for step in actions:
            self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
        self.assertEqual(actions[0]["with"]["persist-credentials"], "false")
        self.assertEqual(actions[1]["with"]["toolchain"], "1.89.0")

    def test_workflow_toolchains_and_cache_keys_are_migrated(self):
        """Require the migrated toolchain and cache keys in both workflows."""
        for name, workflow in (("ci", self.workflow), ("scheduled", self.scheduled)):
            with self.subTest(workflow=name):
                self.assertNotIn("1.88", (ROOT / f".github/workflows/{name}.yml").read_text())
                self.assertEqual(workflow["env"]["RUSTUP_TOOLCHAIN"], "1.89.0")
                for job in workflow["jobs"].values():
                    for step in job["steps"]:
                        action = step.get("uses", "")
                        if action.startswith("dtolnay/rust-toolchain@"):
                            self.assertEqual(step["with"]["toolchain"], "1.89.0")
                        if action.startswith("actions/cache@"):
                            for key in ("key", "restore-keys"):
                                self.assertIn("-1.89.0-", step["with"][key])
        self.assertEqual(self.scheduled["jobs"]["full-linux"]["name"],
                         "full validation (linux, 1.89.0)")
        self.assertEqual(self.scheduled["jobs"]["vuln-extended"]["name"],
                         "extended dependency security scan")

    def run_required_check(self, results):
        """Execute the workflow's required gate with supplied dependency results."""
        step, = self.workflow["jobs"]["required"]["steps"]
        self.assertNotIn("if", step)
        self.assertNotIn("continue-on-error", step)
        self.assertEqual(step["env"]["NEEDS_JSON"], "${{ toJSON(needs) }}")
        lines = step["run"].splitlines()
        self.assertEqual(lines[0], "python3 - <<'EOF'")
        self.assertEqual(lines[-1], "EOF")
        # Execute the workflow's actual gate, not a Python copy of its logic.
        with mock.patch.dict("os.environ", {"NEEDS_JSON": json.dumps(results)}), \
                redirect_stdout(io.StringIO()):
            exec(compile("\n".join(lines[1:-1]), "required CI status", "exec"), {})

    def test_required_aggregate_rejects_unsuccessful_or_missing_native_and_evidence_jobs(self):
        """Require the aggregate gate to reject failed, cancelled, skipped, or absent validation jobs."""
        required = self.workflow["jobs"]["required"]
        self.assertEqual(required["if"], "always()")
        self.assertNotIn("continue-on-error", required)
        self.assertEqual(required["needs"], [
            "clippy", "rust", "native-macos", "generated-rust", "manifest-cases",
            "package", "security", "actionlint", "dependency-review",
        ])
        passing = {job: {"result": "success"} for job in required["needs"]}
        self.run_required_check(passing)
        for job in ("rust", "native-macos", "generated-rust", "manifest-cases"):
            for result in ("failure", "cancelled", "skipped", None):
                with self.subTest(job=job, result=result):
                    results = {**passing, job: {"result": result}}
                    if result is None:
                        del results[job]
                    with self.assertRaises(SystemExit):
                        self.run_required_check(results)

    def test_required_aggregate_preserves_dependency_review_exceptions(self):
        """Allow skipped dependency review or failure without manifests, but reject failure with manifests."""
        passing = {job: {"result": "success"}
                   for job in self.workflow["jobs"]["required"]["needs"]}
        for result, manifests, rejected in (
            ("skipped", None, False),
            ("failure", "false", False),
            ("failure", "true", True),
        ):
            with self.subTest(result=result, manifests=manifests):
                results = {**passing, "dependency-review": {
                    "result": result, "outputs": {"has_manifests": manifests},
                }}
                if rejected:
                    with self.assertRaises(SystemExit):
                        self.run_required_check(results)
                else:
                    self.run_required_check(results)


if __name__ == "__main__":
    unittest.main()
