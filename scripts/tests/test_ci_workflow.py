"""CI evidence and native validation must not weaken required validation gates."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shlex
import sys
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

    def test_generation_check_uses_verified_bebopc(self):
        job = self.workflow['jobs']['generated-rust']
        steps = job['steps']
        setup, = [s for s in steps if s.get('uses') == './.github/actions/setup-bebopc']
        check, = [s for s in steps if s.get('run') == 'python3 scripts/check-generated.py']
        self.assertLess(steps.index(setup), steps.index(check))
        for gate in (job, setup, check):
            self.assertNotIn('if', gate)
            self.assertNotIn('continue-on-error', gate)
        install = (ROOT / '.github/actions/setup-bebopc/action.yml').read_text()
        self.assertIn('/releases/download/v3.2.3/', install)
        self.assertRegex(install, r"'[0-9a-f]{64}  bebopc.zip' \| sha256sum --check")

    def test_parser_budgets_and_main_only_benchmark_trigger(self):
        for workflow, seconds in ((self.workflow, "60"), (self.scheduled, "900")):
            self.assertEqual(workflow["jobs"]["parser-checks"], {
                "uses": "./.github/workflows/parser-checks.yml", "with": {"seconds": seconds},
            })
        bench = yaml.load((ROOT / ".github/workflows/benchmarks.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(bench["on"]), {"push"})
        self.assertEqual(bench["on"]["push"]["branches"], ["main"])
        self.assertEqual(set(bench["on"]["push"]["paths"]), {
            "crates/**/src/**/*.rs",
            "crates/**/benches/**/*.rs",
            "schemas/**/*.bop",
            "bebop.json",
            "crates/syntra-core/tests/bench_allocations.rs",
            "scripts/benchmark_baseline.py",
            "crates/**/build.rs",
            "Cargo.toml",
            "Cargo.lock",
            "crates/**/Cargo.toml",
            "crates/**/Cargo.lock",
            ".cargo/config",
            ".cargo/config.toml",
            "rust-toolchain.toml",
        })
        job = bench["jobs"]["benches"]
        self.assertEqual(job["runs-on"], "blacksmith-4vcpu-ubuntu-2404-arm")
        no_previous_tip = "0" * 40
        self.assertEqual(job["if"], f"${{{{ github.event.before && github.event.before != '{no_previous_tip}' }}}}")
        old, = [step for step in job["steps"] if step.get("with", {}).get("path") == "old"]
        self.assertEqual(old["with"]["ref"], "${{ github.event.before }}")

    def test_codeql_cancels_stale_scans_without_cross_event_cancellation(self):
        codeql = yaml.load((ROOT / ".github/workflows/codeql.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(codeql["concurrency"], {
            "group": "codeql-${{ github.event_name }}-${{ github.ref }}",
            "cancel-in-progress": "true",
        })

    def test_every_wss_scenario_runs_and_preserves_observations(self):
        sys.path.insert(0, str(ROOT / 'scripts'))
        from conformance_evidence import CHANNEL_LANES, SUPPLEMENTAL_SCENARIOS
        job = self.workflow['jobs']['manifest-cases']
        steps = job['steps']
        run, = [s for s in steps if 'scripts/conformance_evidence.py' in s.get('run', '')]
        for gate in (job, run):
            self.assertNotIn('if', gate)
            self.assertNotIn('continue-on-error', gate)
        # The folded YAML step must be one invocation, not flags in comments or another command.
        argv, = [words for line in run['run'].splitlines()
                 if (words := shlex.split(line, comments=True))]
        self.assertEqual(argv[:3], ['python3', '-B', 'scripts/conformance_evidence.py'])
        lanes = SUPPLEMENTAL_SCENARIOS.keys() | CHANNEL_LANES.keys()
        expected = [('--run-local', lane) for lane in lanes] + [('--output', '$RUNNER_TEMP/manifest-cases')]
        self.assertCountEqual(zip(argv[3::2], argv[4::2], strict=True), expected)
        upload, = [s for s in steps if 'upload-artifact' in s.get('uses', '')]
        self.assertLess(steps.index(run), steps.index(upload))
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/manifest-cases')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')

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
        self.assertEqual(self.scheduled["jobs"]["compat-macos"]["runs-on"], "macos-15")
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
                    for step in job.get("steps", []):  # reusable workflow callers have no steps
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
        """Reject failed, cancelled, abandoned, skipped, or absent validation jobs."""
        required = self.workflow["jobs"]["required"]
        self.assertEqual(required["if"], "always()")
        self.assertNotIn("continue-on-error", required)
        self.assertEqual(required["needs"], [
            "clippy", "rust", "native-macos", "generated-rust", "manifest-cases",
            "package", "security", "parser-checks", "actionlint", "dependency-review",
        ])
        passing = {job: {"result": "success"} for job in required["needs"]}
        self.run_required_check(passing)
        for job in ("rust", "native-macos", "generated-rust", "manifest-cases", "parser-checks", "security"):
            for result in ("failure", "cancelled", "abandoned", "skipped", None):
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
