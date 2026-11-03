"""Candidate bytes are not an accepted commit, release approval or CONF execution."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import candidate_rust
import protocol_contract as candidate
from upstream_snapshot import REQUIRED_INPUTS


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "rust"
        self.upstream = Path(temporary.name) / "sdd"
        self.root.mkdir()
        self.upstream.mkdir()
        self.record = candidate.parse_json((candidate.ROOT / candidate.LOCK).read_bytes())
        # Synthetic worktree cases must not depend on the checked-in record's
        # release state. Live-record validation below still uses candidate.ROOT.
        self.record["kind"] = "worktree-not-release"
        self.record["source"].update(dirty=True, candidate_revision=None)
        self.record["source"].pop("worktree_observation", None)
        contexts = (candidate.ROOT / candidate.FIXTURE).read_bytes()
        self.contexts = contexts
        plan = candidate.parse_json(contexts)
        # Exercise normalization even when authoritative source IDs already use
        # the local spelling. Raw source bytes/hashes remain distinct.
        names = {row["id"]: f"source-row-{index}" for index, row in enumerate(plan["contexts"])}
        for row in plan["contexts"]:
            row["id"] = names[row["id"]]
        for index, row in enumerate(plan["negative_recipes"]):
            row.update(id=f"source-negative-{index}", base=names[row["base"]])
        self.source = {
            candidate.INPUTS["contract"]: json.dumps({**self.record["contract"], "owner_mapping": {"external-only.md": "owner.md"}}).encode(),
            candidate.INPUTS["contexts"]: json.dumps(plan, ensure_ascii=False).encode(),
            candidate.INPUTS["vectors"]: json.dumps({"status": "candidate-sdd", "profile": list(self.record["contract"]["carriers"]),
                "vectors": plan["contexts"], "negative_recipes": [{key: row[key] for key in ("id", "base", "mutation", "expected")}
                                                               for row in plan["negative_recipes"]]}).encode(),
            candidate.INPUTS["registry"]: json.dumps({"core_wire_version": 1, "protobuf_package": "syntra.v1",
                "profiles": [{**row, "kind": "TRANSPORT_PROFILE"} for row in self.record["carrier_bindings"]]}).encode(),
        }
        self.record["source"]["files"] = {name: candidate.digest(data) for name, data in self.source.items()}
        self.record["context_fixture"] = candidate.fixture_provenance(self.record["source"], contexts)
        self.record["carrier_bindings_provenance"] = candidate.carrier_provenance(self.record["source"], self.record["carrier_bindings"])
        self.observation = {key: self.record["source"][key] for key in ("baseline_git_head", "branch", "dirty")}
        self.write(self.root, "upstream.lock.json", (candidate.ROOT / "upstream.lock.json").read_bytes())
        self.write(self.root, candidate.FIXTURE, contexts)
        self.save()
        for name, data in self.source.items():
            self.write(self.upstream, name, data)

    @staticmethod
    def write(root, name, data):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def save(self):
        self.write(self.root, candidate.LOCK, json.dumps(self.record).encode())

    def test_offline_never_reads_external_git_or_worktree(self):
        for name in candidate.RUST_INPUTS:
            self.write(self.root, name, b"mocked source\n")
        with mock.patch.object(candidate, "external_source", side_effect=AssertionError("external read")), \
                mock.patch.object(candidate, "git", side_effect=AssertionError("Git read")), \
                mock.patch.object(candidate, "validate_rust", return_value={"kind": "unit oracle"}):
            report = candidate.verify_candidate(self.root, mode="offline")
        self.assertFalse(report["external_bytes_verified"])
        self.assertFalse(report["release_pin_verified"])
        self.assertFalse(report["publication_authorized"])
        self.assertFalse(report["derived_artifacts"]["external_transformations_verified"])

    def test_worktree_verifies_actual_file_bytes_and_semantics(self):
        with mock.patch.object(candidate, "identity", return_value=self.observation):
            contexts, identity = candidate.external_source(self.record, self.upstream, "worktree")
        self.assertEqual(len(contexts["contexts"]), 9)
        self.assertEqual(len(contexts["negative_recipes"]), 36)
        self.assertTrue(identity["dirty"])
        self.assertIsNone(self.record["source"]["candidate_revision"])
        self.assertEqual(contexts, candidate.parse_json(self.contexts))

    def test_context_derivation_preserves_all_non_identifier_fields(self):
        raw = candidate.parse_json(self.source[candidate.INPUTS["contexts"]])
        before = copy.deepcopy(raw)
        normalized = candidate.normalize_contexts(raw)
        self.assertEqual(raw, before)
        self.assertEqual(candidate.normalize_contexts(normalized), normalized)
        self.assertEqual(candidate.fixture_bytes(normalized), self.contexts)
        for index, (source, local) in enumerate(zip(raw["contexts"], normalized["contexts"]), 1):
            self.assertEqual(local, {**source, "id": f"SYNTRA-CONTEXT-{index:02d}"})
        references = {source["id"]: local["id"] for source, local in zip(raw["contexts"], normalized["contexts"])}
        for index, (source, local) in enumerate(zip(raw["negative_recipes"], normalized["negative_recipes"]), 1):
            self.assertEqual(local, {**source, "id": f"SYNTRA-N{index:02d}", "base": references[source["base"]]})

    def test_ambiguous_source_ids_or_missing_base_fail_normalization(self):
        for section, key, value in (("contexts", "id", "source-row-0"),
                                     ("negative_recipes", "id", "source-negative-0"),
                                     ("negative_recipes", "base", "missing")):
            raw = candidate.parse_json(self.source[candidate.INPUTS["contexts"]])
            raw[section][1][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                candidate.normalize_contexts(raw)

    def test_each_external_file_drift_is_rejected_without_writes(self):
        for name, original in self.source.items():
            with self.subTest(name=name):
                path = self.write(self.upstream, name, original + b"\n")
                with mock.patch.object(candidate, "identity", return_value=self.observation), self.assertRaisesRegex(ValueError, "byte drift"):
                    candidate.external_source(self.record, self.upstream, "worktree")
                self.assertEqual(path.read_bytes(), original + b"\n")
                path.write_bytes(original)

    def test_head_branch_or_dirty_change_requires_explicit_rerecord(self):
        for key, value in (("baseline_git_head", "1" * 40), ("branch", "other"), ("dirty", False)):
            with self.subTest(key=key), mock.patch.object(candidate, "identity", return_value={**self.observation, key: value}), \
                    self.assertRaisesRegex(ValueError, "identity changed"):
                candidate.external_source(self.record, self.upstream, "worktree")

    def test_external_verification_has_no_missing_checkout_fallback(self):
        with mock.patch.object(candidate, "identity", side_effect=FileNotFoundError("no SDD")), self.assertRaises(FileNotFoundError):
            candidate.external_source(self.record, self.upstream, "worktree")

    def test_explicit_record_is_small_semantic_copy_and_preserves_accepted_lock(self):
        before = (self.root / "upstream.lock.json").read_bytes()
        with mock.patch.object(candidate, "identity", return_value=self.observation):
            record = candidate.record_worktree(self.root, self.upstream)
        self.assertEqual(record["kind"], "worktree-not-release")
        self.assertEqual(record["source"]["files"], self.record["source"]["files"])
        self.assertNotIn("owner_mapping", record["contract"])
        self.assertEqual(before, (self.root / "upstream.lock.json").read_bytes())
        self.assertFalse(list(self.root.rglob("*.md")))
        self.assertIsNone(record["source"]["candidate_revision"])
        self.assertEqual((self.root / candidate.FIXTURE).read_bytes(), self.contexts)
        self.assertEqual(record["context_fixture"]["source_sha256"], candidate.digest(self.source[candidate.INPUTS["contexts"]]))
        self.assertNotEqual(record["context_fixture"]["sha256"], record["context_fixture"]["source_sha256"])
        self.assertEqual(record["accepted_base"], candidate.accepted_base(self.root))
        self.assertTrue(all(row["kind"] == "CARRIER" for row in record["carrier_bindings"]))
        for name, content in self.source.items():
            self.assertEqual((self.upstream / name).read_bytes(), content)
        candidate.load_record(self.root)

    def test_clean_worktree_capture_still_does_not_promote_to_release_pin(self):
        with mock.patch.object(candidate, "identity", return_value={**self.observation, "dirty": False}):
            record = candidate.record_worktree(self.root, self.upstream)
        with self.assertRaisesRegex(ValueError, "release pin blocked"):
            candidate.release_revision(record)

    def test_racing_identity_refuses_capture_before_writes(self):
        before = (self.root / candidate.LOCK).read_bytes()
        with mock.patch.object(candidate, "identity", side_effect=[self.observation, {**self.observation, "branch": "changed"}]), \
                self.assertRaisesRegex(ValueError, "changed while recording"):
            candidate.record_worktree(self.root, self.upstream)
        self.assertEqual(before, (self.root / candidate.LOCK).read_bytes())

    def test_json_yaml_context_or_negative_drift_is_not_reinterpreted(self):
        for field in ("vectors", "negative_recipes"):
            source = dict(self.source)
            vectors = candidate.parse_json(source[candidate.INPUTS["vectors"]])
            vectors[field].pop()
            source[candidate.INPUTS["vectors"]] = json.dumps(vectors).encode()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "disagree"):
                candidate.source_documents(source)

    def test_registry_policy_drift_is_rejected(self):
        for carrier, key, value in (("SYNTRA-1.0-WS", "production_allowed", True),
                                    ("SYNTRA-1.0-WSS", "tls_minimum", "1.2"),
                                    ("SYNTRA-1.0-WSS", "tls_termination", "proxy"),
                                    ("SYNTRA-1.0-TCP", "binding", "plaintext")):
            rows = copy.deepcopy(self.record["carrier_bindings"])
            next(row for row in rows if row["id"] == carrier)[key] = value
            with self.subTest(carrier=carrier, key=key), self.assertRaises(ValueError):
                candidate.check_registry(self.record["contract"], rows)

    def test_extra_duplicate_or_missing_carriers_are_rejected(self):
        rows = self.record["carrier_bindings"]
        for invalid in (rows[:-1], rows + [rows[0]], [rows[0], rows[0], rows[0]]):
            with self.assertRaises(ValueError):
                candidate.check_registry(self.record["contract"], invalid)

    def test_booleans_cannot_masquerade_as_numeric_contract_fields(self):
        for section, key in ((None, "core_wire_version"), ("channel_limits", "aead_tag_bytes"),
                             ("context_layout", "m2_bytes")):
            contract = copy.deepcopy(self.record["contract"])
            target = contract if section is None else contract[section]
            target[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                candidate.check_registry(contract, self.record["carrier_bindings"])

    def test_transport_suite_kind_cannot_be_selectable_local_protocol(self):
        rows = copy.deepcopy(self.record["carrier_bindings"])
        rows[0]["kind"] = "TRANSPORT_PROFILE"
        with self.assertRaisesRegex(ValueError, "policy mismatch"):
            candidate.check_registry(self.record["contract"], rows)

    def test_derived_provenance_tampering_is_rejected_offline(self):
        for field, key, value in (("context_fixture", "transformation", "unreviewed"),
                                   ("context_fixture", "source_sha256", "0" * 64),
                                   ("carrier_bindings_provenance", "source_sha256", "0" * 64),
                                   ("carrier_bindings_provenance", "transformation", "unreviewed")):
            original = copy.deepcopy(self.record)
            self.record[field][key] = value
            self.save()
            with self.subTest(field=field, key=key), self.assertRaisesRegex(ValueError, "provenance mismatch"):
                candidate.load_record(self.root)
            self.record = original

    def test_raw_source_digest_is_never_substituted_for_derived_digest(self):
        self.record["context_fixture"]["sha256"] = self.record["context_fixture"]["source_sha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "fixture digest"):
            candidate.load_record(self.root)

    def test_external_verification_recomputes_derived_fixture(self):
        # Even a self-consistent local digest cannot prove the transformation
        # without comparing with the recorded raw external input.
        local = candidate.parse_json(self.contexts)
        local["contexts"][0]["scope"] = "b"
        content = candidate.fixture_bytes(local)
        self.record["context_fixture"] = candidate.fixture_provenance(self.record["source"], content)
        self.write(self.root, candidate.FIXTURE, content)
        self.save()
        candidate.load_record(self.root)
        with mock.patch.object(candidate, "identity", return_value=self.observation), \
                self.assertRaisesRegex(ValueError, "transformation drift"):
            candidate.external_source(self.record, self.upstream, "worktree")

    def test_old_candidate_record_or_unscoped_lock_shape_is_not_accepted(self):
        self.record["format_version"] = 1
        self.save()
        with self.assertRaisesRegex(ValueError, "provenance kind"):
            candidate.load_record(self.root)
        self.record["format_version"] = 2
        self.save()
        lock = candidate.parse_json((self.root / "upstream.lock.json").read_bytes())
        lock.pop("scope")
        lock["format_version"] = 1
        self.write(self.root, "upstream.lock.json", json.dumps(lock).encode())
        with self.assertRaisesRegex(ValueError, "snapshot lock identity"):
            candidate.load_record(self.root)

    def test_duplicate_json_keys_and_nan_are_rejected(self):
        for content in ('{"dirty":true,"dirty":false}', '{"value":NaN}'):
            with self.assertRaises(ValueError): candidate.parse_json(content)

    def test_semantic_fixture_and_accepted_lock_tampering_fail_offline(self):
        original = copy.deepcopy(self.record)
        self.record["contract"]["domain_ascii"] = "different"
        self.save()
        with self.assertRaisesRegex(ValueError, "semantic-contract digest"):
            candidate.load_record(self.root)
        self.record = original
        self.save()
        self.write(self.root, candidate.FIXTURE, b"{}")
        with self.assertRaisesRegex(ValueError, "fixture digest"):
            candidate.load_record(self.root)
        self.write(self.root, candidate.FIXTURE, self.contexts)
        self.write(self.root, "upstream.lock.json", (self.root / "upstream.lock.json").read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "accepted-base"):
            candidate.load_record(self.root)

    def test_symlinked_candidate_fixture_is_rejected(self):
        path = self.root / candidate.FIXTURE
        path.unlink()
        path.symlink_to(self.upstream / candidate.INPUTS["contexts"])
        with self.assertRaisesRegex(ValueError, "symlink"):
            candidate.load_record(self.root)

    def test_worktree_baseline_head_is_never_candidate_commit(self):
        self.record["source"]["candidate_revision"] = self.observation["baseline_git_head"]
        self.save()
        with self.assertRaisesRegex(ValueError, "masquerade"):
            candidate.load_record(self.root)

    def test_changing_kind_alone_cannot_invent_committed_candidate_metadata(self):
        self.record["kind"] = "committed-candidate"
        self.save()
        with self.assertRaisesRegex(ValueError, "release pin blocked"):
            candidate.load_record(self.root)

    def test_release_metadata_refuses_dirty_missing_short_and_zero_revisions(self):
        for kind, dirty, revision in (("worktree-not-release", True, None), ("committed-candidate", True, "1" * 40),
                                      ("committed-candidate", False, "HEAD"), ("committed-candidate", False, "0" * 40)):
            record = copy.deepcopy(self.record)
            record["kind"] = kind
            record["source"].update(dirty=dirty, candidate_revision=revision)
            with self.subTest(kind=kind, dirty=dirty, revision=revision), self.assertRaisesRegex(ValueError, "release pin blocked"):
                candidate.release_revision(record)

    def test_fabricated_commit_cannot_promote_record_without_git_objects(self):
        before = (self.root / candidate.LOCK).read_bytes()
        with mock.patch.object(candidate, "git", side_effect=subprocess.CalledProcessError(128, ["git"])), \
                self.assertRaises(subprocess.CalledProcessError):
            candidate.record_commit("1" * 40, self.root, self.upstream)
        self.assertEqual(before, (self.root / candidate.LOCK).read_bytes())

    def fake_git(self, upstream, *args):
        if args[0] == "rev-parse": return b"1111111111111111111111111111111111111111\n"
        if args[0] == "merge-base": return b""
        if args[0] == "ls-tree": return ("100644 blob " + "a" * 40 + "\t" + args[-1] + "\n").encode()
        if args[0] == "show": return self.source[args[1].split(":", 1)[1]]
        self.fail(f"unexpected Git read: {args}")

    def test_committed_pin_promotion_requires_actual_matching_regular_git_blobs(self):
        with mock.patch.object(candidate, "git", side_effect=self.fake_git) as git:
            record = candidate.record_commit("1" * 40, self.root, self.upstream)
        self.assertEqual(record["kind"], "committed-candidate")
        self.assertTrue(record["source"]["worktree_observation"]["dirty"])
        self.assertFalse(record["source"]["dirty"])
        self.assertEqual(candidate.release_revision(record), "1" * 40)
        self.assertEqual(sum(call.args[1] == "show" for call in git.call_args_list), 4)

    def test_commit_with_different_bytes_cannot_promote_record(self):
        self.source[candidate.INPUTS["contract"]] += b"\n"
        before = (self.root / candidate.LOCK).read_bytes()
        with mock.patch.object(candidate, "git", side_effect=self.fake_git), self.assertRaisesRegex(ValueError, "byte drift"):
            candidate.record_commit("1" * 40, self.root, self.upstream)
        self.assertEqual(before, (self.root / candidate.LOCK).read_bytes())

    def test_candidate_git_input_cannot_be_symlink_or_executable_blob(self):
        for mode in ("120000", "100755"):
            def read(upstream, *args):
                value = self.fake_git(upstream, *args)
                return value.replace(b"100644", mode.encode()) if args[0] == "ls-tree" else value
            with self.subTest(mode=mode), mock.patch.object(candidate, "git", side_effect=read), self.assertRaisesRegex(ValueError, "regular nonexecutable"):
                candidate.record_commit("1" * 40, self.root, self.upstream)

    def fixture_git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.name=Syntra fixture", "-c", "user.email=syntra-fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
            cwd=self.upstream, check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()

    def fixture_commit(self, message):
        self.fixture_git("add", "--all")
        self.fixture_git("commit", "-m", message)
        return self.fixture_git("rev-parse", "HEAD")

    def matching_git_candidate(self):
        self.fixture_git("init", "--initial-branch=candidate", "--object-format=sha1")
        name = candidate.INPUTS["contract"]
        self.write(self.upstream, name, b"baseline input\n")
        baseline = self.fixture_commit("Baseline fixture")
        self.write(self.upstream, name, self.source[name])
        revision = self.fixture_commit("Matching candidate fixture")
        self.record["source"].update(baseline_git_head=baseline, branch="candidate")
        self.observation = {key: self.record["source"][key] for key in ("baseline_git_head", "branch", "dirty")}
        self.save()
        return revision

    def local_candidate_artifacts(self):
        return {name: (self.root / name).read_bytes()
                for name in (candidate.LOCK, candidate.FIXTURE, "upstream.lock.json")}

    def test_real_git_promotion_preserves_dirty_observation_fixture_and_accepted_lock(self):
        revision = self.matching_git_candidate()
        before = self.local_candidate_artifacts()
        record = candidate.record_commit(revision, self.root, self.upstream)
        expected = copy.deepcopy(self.record)
        expected.update(kind="committed-candidate", recorded_utc=record["recorded_utc"])
        expected["source"].update(candidate_revision=revision, dirty=False,
                                  worktree_observation=self.observation)
        self.assertEqual(record, expected)
        self.assertEqual(candidate.load_record(self.root), expected)
        self.assertEqual(candidate.release_revision(record), revision)
        for name in (candidate.FIXTURE, "upstream.lock.json"):
            self.assertEqual((self.root / name).read_bytes(), before[name])
        contexts, observed = candidate.external_source(record, self.upstream, "release")
        self.assertEqual(contexts, candidate.parse_json(self.contexts))
        self.assertEqual(observed, {"candidate_revision": revision, "kind": "exact_committed_git_blobs"})

    def test_real_git_changed_input_cannot_be_rescued_by_matching_worktree_or_rewrite_record(self):
        revision = self.matching_git_candidate()
        record = candidate.record_commit(revision, self.root, self.upstream)
        before = self.local_candidate_artifacts()
        name = candidate.INPUTS["contract"]
        self.write(self.upstream, name, self.source[name] + b"\n")
        changed = self.fixture_commit("Changed candidate input")
        self.write(self.upstream, name, self.source[name])
        with self.assertRaisesRegex(ValueError, "byte drift"):
            candidate.record_commit(changed, self.root, self.upstream)
        changed_record = copy.deepcopy(record)
        changed_record["source"]["candidate_revision"] = changed
        with self.assertRaisesRegex(ValueError, "byte drift"):
            candidate.external_source(changed_record, self.upstream, "release")
        # Moving HEAD to the bad descendant does not invalidate the original pin.
        contexts, observed = candidate.external_source(record, self.upstream, "release")
        self.assertEqual(contexts, candidate.parse_json(self.contexts))
        self.assertEqual(observed["candidate_revision"], revision)
        self.assertEqual(self.local_candidate_artifacts(), before)
        self.assertEqual((self.upstream / name).read_bytes(), self.source[name])

    def test_real_git_dirty_or_missing_worktree_inputs_do_not_affect_release_blob_proof(self):
        revision = self.matching_git_candidate()
        for name in self.source:
            (self.upstream / name).unlink()
        name = candidate.INPUTS["contract"]
        dirty = b"uncommitted bytes must not be used or rewritten\n"
        self.write(self.upstream, name, dirty)
        record = candidate.record_commit(revision, self.root, self.upstream)
        before = self.local_candidate_artifacts()
        contexts, observed = candidate.external_source(record, self.upstream, "release")
        self.assertEqual(contexts, candidate.parse_json(self.contexts))
        self.assertEqual(observed, {"candidate_revision": revision, "kind": "exact_committed_git_blobs"})
        self.assertEqual(self.local_candidate_artifacts(), before)
        self.assertEqual((self.upstream / name).read_bytes(), dirty)
        self.assertTrue(all(not (self.upstream / other).exists() for other in self.source if other != name))

    def test_rust_control_zero_or_ignored_tests_do_not_pass(self):
        for text, expected in (("test result: ok. 0 passed; 0 failed; 0 ignored;", "NOT_EXECUTED"),
                               ("test result: ok. 0 passed; 0 failed; 1 ignored;", "SKIP")):
            def run(command, **kwargs):
                self.assertIn("--exact", command)
                self.assertIn("--locked", command)
                self.assertEqual(kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.88.0")
                kwargs["stdout"].write(text)
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(candidate.subprocess, "run", side_effect=run):
                results = candidate.run_rust_agreement(Path(directory) / "new")
                self.assertEqual(len(results), 5)
                self.assertTrue(all(row["verdict"] == expected and not row["formal_conformance"] for row in results))

    def test_rust_agreement_uses_exact_package_target_and_qualified_test_names(self):
        expected = [
            ("kernel-contexts", ["-p", "syntra-core", "--lib"],
             "secure_channel::context_tests::four_candidate_context_and_prologue_fixtures"),
            ("native-binding", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "wss"],
             "invalid_endpoints_and_carrier_mismatches_do_not_open_socket"),
            ("native-tls13", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "wss"],
             "wss_server_rejects_tls12_client_before_authentication"),
            ("loopback-ws", ["-p", "syntra-transport", "--no-default-features", "--features", "websocket", "--test", "websocket"],
             "ws_rejects_non_loopback_and_secure_carrier"),
            ("browser-context", ["-p", "syntra-web", "--no-default-features", "--features", "browser-connection", "--test", "connection_records"],
             "browser_wss_context_uses_candidate_syntra_1_0_bytes"),
        ]

        def run(command, **kwargs):
            test = command[command.index("--") - 1]
            kwargs["stdout"].write(f"test {test} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(candidate.subprocess, "run", side_effect=run) as cargo:
            results = candidate.run_rust_agreement(Path(directory) / "new")
            self.assertEqual(cargo.call_count, len(expected))
            self.assertEqual(len(results), len(expected))
            for result, call, (lane, selector, test) in zip(results, cargo.call_args_list, expected):
                command = ["cargo", "test", "--locked", *selector, test,
                           "--", "--exact", "--show-output", "--color", "never"]
                self.assertEqual(call.args[0], command)
                self.assertEqual(call.kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.88.0")
                self.assertEqual((result["lane"], result["command"], result["test"]), (lane, command, test))
                self.assertEqual(result["verdict"], "PASS")
                self.assertFalse(result["formal_conformance"])
                self.assertEqual(result["log_sha256"], candidate.digest(Path(result["log"]).read_bytes()))

    def test_kernel_agreement_requires_the_fully_qualified_execution_name(self):
        def run(command, **kwargs):
            test = command[command.index("--") - 1]
            if command[command.index("-p") + 1] == "syntra-core":
                test = test.removeprefix("secure_channel::")
            kwargs["stdout"].write(f"test {test} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(candidate.subprocess, "run", side_effect=run):
            results = candidate.run_rust_agreement(Path(directory) / "new")
        self.assertEqual(results[0]["lane"], "kernel-contexts")
        self.assertEqual(results[0]["verdict"], "NOT_EXECUTED")
        self.assertTrue(all(result["verdict"] == "PASS" for result in results[1:]))


class RustAgreementTests(unittest.TestCase):
    def test_kernel_and_native_fixture_paths_use_core_boundaries(self):
        self.assertEqual(candidate_rust.KERNEL, "crates/syntra-core/src/secure_channel/mod.rs")
        self.assertEqual(candidate_rust.NATIVE_FIXTURES, "crates/syntra-core/tests/fixtures/syntra_1_0_context.rs")
        self.assertIn(candidate_rust.KERNEL, candidate.RUST_INPUTS)
        self.assertIn(candidate_rust.NATIVE_FIXTURES, candidate.RUST_INPUTS)

    def test_current_candidate_paths_do_not_rewrite_accepted_base_keys(self):
        self.assertEqual(candidate.INPUTS["contexts"], "conformance/test-vectors/connection/context-vectors.json")
        self.assertEqual(candidate.INPUTS["vectors"], "conformance/test-vectors/connection/context-vectors.yaml")
        accepted = candidate.read_lock(candidate.ROOT)
        self.assertEqual(set(accepted), set(REQUIRED_INPUTS))
        self.assertNotIn(candidate.INPUTS["contexts"], accepted)
        self.assertNotIn(candidate.INPUTS["vectors"], accepted)
        binding = candidate.load_record()["accepted_base"]
        self.assertEqual(binding["scope"], "implementation-inputs")
        self.assertEqual(binding["lock_format_version"], 2)
        self.assertEqual(binding["input_count"], len(REQUIRED_INPUTS))
        self.assertEqual(binding["lock_sha256"], candidate.digest((candidate.ROOT / "upstream.lock.json").read_bytes()))

    def test_actual_rust_constants_context_parser_and_independent_fixtures(self):
        # Live rustc probe only: no crate edits, Cargo test selection or carrier.
        report = candidate.verify_candidate(mode="offline")
        self.assertEqual(report["agreement"]["contexts"], 9)
        self.assertEqual(report["agreement"]["negative_parser_recipes"], 36)
        self.assertEqual(report["agreement"]["independent_native_fixtures"], 4)
        self.assertFalse(report["publication_authorized"])

    def test_negative_coverage_requires_reviewed_recipes_not_an_arbitrary_count(self):
        record = candidate.load_record()
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        for change in ("missing", "duplicate-case", "duplicate-id", "missing-id", "unreviewed",
                       "wrong-expectation", "missing-base", "absent-base"):
            invalid = copy.deepcopy(contexts)
            rows = invalid["negative_recipes"]
            if change == "missing": rows.pop()
            elif change == "duplicate-case": rows[-1].update(base=rows[0]["base"], mutation=rows[0]["mutation"])
            elif change == "duplicate-id": rows[-1]["id"] = rows[0]["id"]
            elif change == "missing-id": rows[-1].pop("id")
            elif change == "unreviewed": rows[-1]["mutation"] = "unreviewed"
            elif change == "wrong-expectation": rows[-1]["expected"] = "accept"
            elif change == "missing-base": rows[-1]["base"] = "missing"
            else: rows[-1].pop("base")
            with self.subTest(change=change), mock.patch.object(candidate, "probe", side_effect=AssertionError("probe ran")), \
                    self.assertRaisesRegex(ValueError, "negative fixture coverage"):
                candidate.validate_rust(candidate.ROOT, record["contract"], invalid)

    def test_repeated_mutations_across_carriers_have_complete_reviewed_coverage(self):
        contract = candidate.load_record()["contract"]
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        coverage = candidate.check_context_coverage(contract, contexts)
        self.assertEqual(coverage, [{"carrier": carrier, "mutations": sorted(candidate.NEGATIVE_MUTATIONS)}
                                    for carrier in (1, 2, 3)])
        for mutation in candidate.NEGATIVE_MUTATIONS:
            self.assertEqual(sum(row["mutation"] == mutation for row in contexts["negative_recipes"]), 3)

    def test_missing_per_carrier_coverage_cannot_be_replaced_by_other_base_cases(self):
        contract = candidate.load_record()["contract"]
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        # Keep 36 unique (base, mutation) cases and every global mutation,
        # but move one WSS case onto a distinct TCP returning base.
        row = next(row for row in contexts["negative_recipes"]
                   if row["mutation"] == "returning-handle" and row["base"] == "SYNTRA-CONTEXT-04")
        row["base"] = "SYNTRA-CONTEXT-07"
        with self.assertRaisesRegex(ValueError, "coverage missing on carrier 3"):
            candidate.check_context_coverage(contract, contexts)

    def test_context_coverage_rejects_missing_or_unknown_carrier_and_mode(self):
        contract = candidate.load_record()["contract"]
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        for field, value in (("carrier", 4), ("carrier", None), ("carrier", True),
                             ("mode", 3), ("mode", None), ("mode", True)):
            invalid = copy.deepcopy(contexts)
            if value is None: invalid["contexts"][0].pop(field)
            else: invalid["contexts"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "unknown carrier/mode"):
                candidate.check_context_coverage(contract, invalid)
        for field, value in (("carrier", 2), ("mode", 2)):
            invalid = copy.deepcopy(contexts)
            invalid["contexts"] = [row for row in invalid["contexts"] if row[field] != value]
            with self.subTest(missing_field=field), self.assertRaisesRegex(ValueError, "both modes on every carrier"):
                candidate.check_context_coverage(contract, invalid)

    def test_recipe_base_modes_and_scope_semantics_are_required(self):
        contract = candidate.load_record()["contract"]
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        for mutation in candidate.NEGATIVE_MUTATIONS:
            invalid = copy.deepcopy(contexts)
            recipe = next(row for row in invalid["negative_recipes"] if row["mutation"] == mutation)
            recipe["base"] = "SYNTRA-CONTEXT-01" if mutation in ("returning-handle", "scope-byte-length") else "SYNTRA-CONTEXT-05"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "requires base mode"):
                candidate.check_context_coverage(contract, invalid)
        for mutation, base, reason in (("scope-byte-length", "SYNTRA-CONTEXT-05", "multibyte scope"),
                                       ("invalid-utf8", "SYNTRA-CONTEXT-02", "single-byte scope")):
            invalid = copy.deepcopy(contexts)
            next(row for row in invalid["negative_recipes"] if row["mutation"] == mutation)["base"] = base
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, reason):
                candidate.check_context_coverage(contract, invalid)

    def test_neutral_domain_and_format_recipes_match_source_attack_bytes(self):
        contract = candidate.load_record()["contract"]
        contexts = candidate.parse_json((candidate.ROOT / candidate.FIXTURE).read_bytes())
        rows = {row["id"]: row for row in contexts["contexts"]}
        for row in contexts["negative_recipes"]:
            if row["mutation"] not in ("unsupported-domain", "unsupported-format"): continue
            base = rows[row["base"]]
            mutated = candidate_rust.negative_bytes(row, base, contract["context_layout"])
            if row["mutation"] == "unsupported-domain":
                self.assertEqual(mutated, b"invalid.00" + bytes.fromhex(base["context_hex"])[10:])
            else:
                self.assertEqual(mutated, bytes(8))
        with self.assertRaisesRegex(ValueError, "unreviewed negative recipe"):
            candidate_rust.negative_bytes({"mutation": "unreviewed"}, rows["SYNTRA-CONTEXT-01"], contract["context_layout"])

    def test_array_semicolon_does_not_truncate_actual_rust_constant(self):
        source = "const A: usize = size_of::<[u8; 8]>();\n"
        self.assertEqual(candidate_rust.const(source, "A"), source.strip())

    def test_duplicate_or_missing_rust_boundary_is_not_guessed(self):
        for source in ("", 'pub const PROTOCOL: &str = "a";\npub const PROTOCOL: &str = "b";\n'):
            with self.assertRaises(ValueError): candidate_rust.const(source, "PROTOCOL")

    def test_block_parser_ignores_comment_and_string_braces(self):
        source = 'impl Context {\n// }\nfn f() { let s = "}"; }\n}\n'
        self.assertEqual(candidate_rust.block(source, "impl Context"), source.strip())

    def test_binding_guard_drift_is_detected_without_claiming_runtime_execution(self):
        root = candidate.ROOT
        record = candidate.load_record()
        def read(where, name):
            value = (root / name).read_bytes()
            return value.replace(b'"wss" if carrier == Carrier::SecureWebSocket', b'"wss" if false')
        with mock.patch.object(candidate_rust, "regular_file", side_effect=read), self.assertRaisesRegex(ValueError, "native WSS carrier"):
            candidate_rust.binding_sources(root, record["contract"])

    def test_browser_independent_bounds_drift_is_detected(self):
        root = candidate.ROOT
        def read(where, name):
            return (root / name).read_bytes().replace(b"data.length >= 83", b"data.length >= 84")
        with mock.patch.object(candidate_rust, "regular_file", side_effect=read), self.assertRaisesRegex(ValueError, "JS M1 bounds"):
            candidate_rust.browser_fixture_bounds(root, candidate.load_record()["contract"])


if __name__ == "__main__":
    unittest.main()
