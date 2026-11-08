"""CI evidence uploads must follow execution without weakening validation gates."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class CiWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        cls.steps = cls.workflow["jobs"]["rust"]["steps"]

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


if __name__ == "__main__":
    unittest.main()
