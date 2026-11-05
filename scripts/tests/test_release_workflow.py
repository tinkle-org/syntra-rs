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
        self.assertEqual(self.workflow["on"]["push"], {"branches": ["main"]})
        self.assertNotIn("concurrency", self.workflow)
        jobs = self.workflow["jobs"]
        self.assertNotIn("concurrency", jobs["release-plz-release"])
        self.assertEqual(jobs["release-plz-pr"]["concurrency"]["cancel-in-progress"], "false")

    def test_publication_requires_validation_without_oidc_permissions(self):
        jobs = self.workflow["jobs"]
        release = jobs["release-plz-release"]
        self.assertEqual(release["needs"], ["validate-release"])
        self.assertEqual(release["environment"], "crates-io-publish")
        self.assertEqual(release["if"], "github.repository_owner == 'tinkle-org' && github.ref == 'refs/heads/main'")
        for job in jobs.values():
            self.assertNotIn("id-token", job["permissions"])
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
            self.assertEqual(action["env"]["GITHUB_TOKEN"], "${{ secrets.GITHUB_TOKEN }}")
            expected = {"GITHUB_TOKEN"}
            if command == "release":
                expected.add("CARGO_REGISTRY_TOKEN")
                self.assertEqual(action["env"]["CARGO_REGISTRY_TOKEN"], "${{ secrets.CARGO_REGISTRY_TOKEN }}")
            self.assertEqual(set(action["env"]), expected)
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            # Comments may document the prohibition, but no parsed workflow
            # field may introduce this credential (including checkout inputs).
            workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            self.assertNotIn("RELEASE_PLZ_TOKEN", str(workflow), str(path))

    def test_registry_secret_is_scoped_only_to_the_publication_step(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/release-plz.yml").read_text(), Loader=yaml.BaseLoader)
        release = workflow["jobs"]["release-plz-release"]
        action, = [step for step in release["steps"] if step.get("with", {}).get("command") == "release"]
        del action["env"]["CARGO_REGISTRY_TOKEN"]
        self.assertNotIn("CARGO_REGISTRY_TOKEN", str(workflow))

    def test_manual_retry_checks_a_merged_release_commit_before_validation(self):
        dispatch = self.workflow["on"]["workflow_dispatch"]
        self.assertEqual(set(dispatch["inputs"]), {"release_commit"})
        self.assertEqual(dispatch["inputs"]["release_commit"]["required"], "true")
        self.assertEqual(dispatch["inputs"]["release_commit"]["type"], "string")
        jobs = self.workflow["jobs"]
        self.assertEqual(jobs["release-plz-pr"]["if"], "github.repository_owner == 'tinkle-org' && github.event_name == 'push'")
        steps = jobs["validate-release"]["steps"]
        self.assertEqual(steps[0]["if"], "github.event_name == 'workflow_dispatch'")
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', steps[0]["run"])
        self.assertIn('[[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]', steps[0]["run"])
        proof, = [step for step in steps if "git merge-base" in step.get("run", "")]
        self.assertEqual(proof["if"], "github.event_name == 'workflow_dispatch'")
        for guard in ('git merge-base --is-ancestor "$RELEASE_COMMIT" origin/main',
                      'git rev-parse --verify "${RELEASE_COMMIT}^2"',
                      '.merged_at != null', '.base.ref == "main"',
                      '.merge_commit_sha == env.RELEASE_COMMIT', 'startswith("release-plz-")'):
            self.assertIn(guard, proof["run"])
        candidate = next(step for step in steps if "--release-revision" in step.get("run", ""))
        self.assertLess(steps.index(proof), steps.index(candidate))
        for name in ("validate-release", "release-plz-release"):
            checkout, = [step for step in jobs[name]["steps"] if step.get("uses", "").startswith("actions/checkout@")]
            self.assertEqual(checkout["with"]["ref"], "${{ inputs.release_commit || github.sha }}")
            self.assertEqual(checkout["with"]["persist-credentials"], "false")

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
