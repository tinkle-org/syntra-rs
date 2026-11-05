"""Release automation must preserve merge events and publication gates."""

from pathlib import Path
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # BaseLoader keeps GitHub's `on` key and scalar spellings intact.
        cls.workflow = yaml.load(
            (ROOT / ".github/workflows/release-plz.yml").read_text(), Loader=yaml.BaseLoader)
        cls.config = tomllib.loads((ROOT / "release-plz.toml").read_text())

    def test_merge_events_are_not_replaced_by_workflow_concurrency(self):
        self.assertEqual(self.workflow["on"], {"push": {"branches": ["main"]}})
        self.assertNotIn("concurrency", self.workflow)
        jobs = self.workflow["jobs"]
        self.assertNotIn("concurrency", jobs["release-plz-release"])
        self.assertEqual(jobs["release-plz-pr"]["concurrency"]["cancel-in-progress"], "false")

    def test_publication_requires_validation_and_keeps_oidc_scoped(self):
        jobs = self.workflow["jobs"]
        release = jobs["release-plz-release"]
        self.assertEqual(release["needs"], ["validate-release"])
        self.assertEqual(release["environment"], "crates-io-publish")
        self.assertEqual(release["if"], "github.repository_owner == 'tinkle-org'")
        self.assertEqual(release["permissions"]["id-token"], "write")
        for name in ("validate-release", "release-plz-pr"):
            self.assertNotIn("id-token", jobs[name]["permissions"])
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_rc_publication_retains_verification_and_release_pr_gate(self):
        config = self.config["workspace"]
        self.assertFalse(config["release_always"])
        self.assertFalse(config["publish_no_verify"])
        self.assertFalse(config["publish_all_features"])
        self.assertFalse(config["publish_allow_dirty"])
        self.assertEqual(config["git_release_type"], "auto")
        self.assertTrue(config["git_release_enable"])
        self.assertTrue(config["git_tag_enable"])

    def test_both_release_jobs_use_only_the_builtin_github_token(self):
        for job, command in (
            ("release-plz-pr", "release-pr"),
            ("release-plz-release", "release"),
        ):
            steps = self.workflow["jobs"][job]["steps"]
            action, = [step for step in steps if step.get("with", {}).get("command") == command]
            self.assertEqual(action["env"], {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"})
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            # Comments may document the prohibition, but no parsed workflow
            # field may introduce this credential (including checkout inputs).
            workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            self.assertNotIn("RELEASE_PLZ_TOKEN", str(workflow), str(path))

    def test_validation_checks_candidate_before_builds(self):
        validation = self.workflow["jobs"]["validate-release"]
        self.assertEqual(self.workflow["env"]["RUSTUP_TOOLCHAIN"], "1.88.0")
        steps = validation["steps"]
        runs = [step["run"] for step in steps if "run" in step]
        candidate, = [run for run in runs if "--release-revision" in run]
        self.assertIn('--release --upstream "$SYNTRA_SDD_ROOT"', candidate)
        self.assertLess(runs.index(candidate), next(i for i, run in enumerate(runs) if "cargo test" in run))
        checks = "\n".join(runs)
        for required in (
            "cargo test --locked\n", "cargo test --locked --workspace",
            "--features managed,proxy,tls-rustls,native-enrollment,http",
            "--features production", "--features test-fixture",
            "--target wasm32-unknown-unknown", "cargo audit --deny warnings",
            "cargo deny --locked check advisories licenses sources",
            "cargo build --locked --release -p syntra-ffi",
            "python3 scripts/cargo_contracts.py package",
        ):
            with self.subTest(required=required):
                self.assertIn(required, checks)
        self.assertNotIn("--all-features", checks)
        self.assertNotIn("continue-on-error", validation)
        for step in steps:
            self.assertNotIn("continue-on-error", step)


if __name__ == "__main__":
    unittest.main()
