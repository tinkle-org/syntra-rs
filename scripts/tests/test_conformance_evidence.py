"""Evidence must come from local fixtures and an observed exact test run."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conformance_evidence as evidence
import protocol_contract


class FixtureTests(unittest.TestCase):
    def test_actual_contexts_and_negative_recipes(self):
        report = protocol_contract.verify()
        self.assertEqual((report['contexts'], report['negative_recipes']), (9, 36))
        self.assertEqual(len(report['carriers']), 3)

    def test_missing_and_misassigned_manifest_recipes_fail(self):
        root = evidence.ROOT
        fixtures = root / evidence.FIXTURES
        contract = json.loads((root / 'protocol-contract.json').read_text())
        vectors = json.loads((fixtures / 'syntra-1.0-context.json').read_text())
        for wrong in (None, 'SYNTRA-N15'):
            cases = json.loads((fixtures / 'context-cases.json').read_text())
            recipes = cases['SYNTRA-1.0-TCP']['recipes']
            recipes.pop()
            if wrong:
                recipes.append(wrong)
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                protocol_contract.coverage(contract, vectors, cases)

    def test_local_transport_fixture_matches_rust_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for rel in (evidence.FIXTURES / 'transport.yaml', Path('tests/interoperability/vectors.rs')):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(evidence.ROOT / rel, root / rel)
            report = evidence.verify_transcriptions(root)
            self.assertEqual(report['verdict'], 'PASS')
            self.assertFalse(report['formal_conformance'])
            f = root / evidence.FIXTURES / 'transport.yaml'
            original = f.read_text()
            for value in ('890670696e672d31', '1005', '1001', '1048576'):
                f.write_text(original.replace(value, '9999'))
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'transcription drift'):
                    evidence.verify_transcriptions(root)

    def test_ambiguous_or_unsafe_yaml_is_rejected(self):
        for text in ('x: 1\nx: 2', '1: x', '!!python/object/apply:os.system [false]'):
            with self.subTest(text=text), self.assertRaises((ValueError, evidence.yaml.YAMLError)):
                evidence.load_yaml(text)


class EvidenceTests(unittest.TestCase):
    def test_scenario_fixture_must_match_initial_worktree_identity(self):
        path = evidence.SCENARIO_FIXTURE.as_posix()
        with mock.patch.object(sys, 'argv', ['evidence']), \
                mock.patch.object(evidence, 'implementation_identity', return_value={'files': {path: 'other digest'}}), \
                self.assertRaisesRegex(ValueError, 'fixture digest'):
            evidence.main()

    def test_execution_requires_one_named_test(self):
        summary = 'test result: ok. 1 passed; 0 failed; 0 ignored;'
        for text, expected in (('test wanted ... ok\n' + summary, 'PASS'),
                               ('test other ... ok\n' + summary, 'NOT_EXECUTED'),
                               (summary.replace('1 passed', '0 passed'), 'NOT_EXECUTED'),
                               ('test wanted ... ok\n' + summary + '\n' + summary, 'NOT_EXECUTED'),
                               ('test result: ok. 0 passed; 0 failed; 1 ignored;', 'SKIP')):
            with self.subTest(text=text):
                self.assertEqual(evidence.local_verdict(0, text, 'wanted')[0], expected)

    def test_changed_worktree_or_unsuccessful_lane_invalidates_report(self):
        files = {evidence.SCENARIO_FIXTURE.as_posix(): evidence.digest((evidence.ROOT / evidence.SCENARIO_FIXTURE).read_bytes())}
        for changed, verdict, expected in [(False, 'PASS', 0), (True, 'PASS', 1), (False, 'SKIP', 1)]:
            with self.subTest(changed=changed, verdict=verdict), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'evidence'
                args = ['evidence', '--output', str(output), '--run-local', 'corpus', '--run-local', 'corpus']
                with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()), \
                        mock.patch.object(evidence, 'verify_protocol', return_value={}), \
                        mock.patch.object(evidence, 'implementation_identity', side_effect=[{'files': files}, {'files': {**files, 'x': 1} if changed else files}]), \
                        mock.patch.object(evidence, 'run_local', return_value={'verdict': verdict}) as run:
                    self.assertEqual(evidence.main(), expected)
                run.assert_called_once_with('corpus', output)
                report = json.loads((output / 'report.json').read_text())
                self.assertFalse(report['formal_conformance_claimed'])
                self.assertEqual(report['supplemental_results'][0]['verdict'], 'NOT_EXECUTED' if changed else verdict)

    def test_existing_and_inside_worktree_outputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (directory, evidence.ROOT / 'invalid-evidence-output'):
                with mock.patch.object(sys, 'argv', ['evidence', '--output', str(path)]), self.assertRaises(ValueError):
                    evidence.main()
