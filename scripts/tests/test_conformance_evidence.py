"""Evidence must come from local fixtures and an observed exact test run."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
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
        self.assertEqual(report['encoding'], 'Protobuf')
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

    def test_ambiguous_yaml_keys_raise_value_error(self):
        for text in ('x: 1\nx: 2', '1: x'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'non-string or duplicate YAML key'):
                evidence.load_yaml(text)

    def test_unsupported_yaml_tags_raise_constructor_error(self):
        for tag, text in [('omap', '!!omap [{x: 1}, {x: 2}]'), ('pairs', 'nested: !!pairs [{1: x}]'),
                          ('omap', '<<: !!omap [{x: 1}]'), ('python/object', '!!python/object/apply:os.system [false]')]:
            with self.subTest(text=text), self.assertRaisesRegex(evidence.yaml.constructor.ConstructorError, tag):
                evidence.load_yaml(text)


class TranscriptionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.transport = evidence.FIXTURES / 'transport.yaml'
        self.hello = evidence.FIXTURES / 'ws-no-length-prefix.hex'
        self.corpus = evidence.FIXTURES / 'protobuf-vectors.yaml'
        self.vectors = Path('tests/interoperability/vectors.rs')
        for rel in (self.transport, self.hello, self.corpus, self.vectors):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(evidence.ROOT / rel, self.root / rel)

    def test_local_transport_fixture_matches_rust_and_detects_drift(self):
        report = evidence.verify_transcriptions(self.root)
        self.assertEqual(report['kind'], 'fixture_transcription_only')
        self.assertEqual(report['verdict'], 'PASS')
        self.assertFalse(report['formal_conformance'])
        f = self.root / self.transport
        self.assertEqual(report['origins'], {p.as_posix(): evidence.digest((self.root / p).read_bytes())
                                             for p in (self.transport, self.hello, self.corpus)})
        self.assertEqual(report['source_sha256'], evidence.digest((self.root / self.vectors).read_bytes()))
        original = f.read_text()
        for value in ('890670696e672d31', '1005', '1001', '1048576'):
            f.write_text(original.replace(value, '9999'))
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'transcription drift'):
                evidence.verify_transcriptions(self.root)

    def test_only_reviewed_hex_declarations_and_values_pass(self):
        vectors = self.root / self.vectors
        original = vectors.read_text()
        ping = next(line for line in original.splitlines() if line.startswith('pub const PING_WIRE_HEX'))
        for change, edited in [('extra', original + '\npub const EXTRA_HEX: &str = "ff";'),
                               ('nonliteral extra', original + '\npub const EXTRA_HEX: &str = PING_WIRE_HEX;'),
                               ('duplicate', original + '\n' + ping), ('commented out', original.replace(ping, '//' + ping))]:
            vectors.write_text(edited)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'WS vector transcription drift'):
                evidence.verify_transcriptions(self.root)

    def test_changed_hello_bytes_fail_without_a_change_to_the_origin_pin(self):
        (self.root / self.hello).write_text('00\n')
        with self.assertRaisesRegex(ValueError, 'VEC-WS-009 hello fixture drift'):
            evidence.verify_transcriptions(self.root)

    def test_local_protobuf_corpus_pins_ids_bytes_and_metadata(self):
        corpus = self.root / self.corpus
        crlf = corpus.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        corpus.write_bytes(crlf)
        report = evidence.verify_transcriptions(self.root)
        self.assertEqual(report['origins'][self.corpus.as_posix()], evidence.digest(crlf))
        for old, new in [(b'GOLD-PROT-HELLO-01', b'other'), (b'd2050178', b'd2050179'),
                         (b'unknown_field_scope: Frame', b'unknown_field_scope: RpcRequest')]:
            corpus.write_bytes(crlf.replace(old, new))
            with self.subTest(old=old), self.assertRaisesRegex(ValueError, 'local Protobuf corpus drift'):
                evidence.verify_transcriptions(self.root)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        path = evidence.SCENARIO_FIXTURE
        self.identity = {'files': {path.as_posix(): evidence.digest((evidence.ROOT / path).read_bytes())}}

    def test_scenario_fixture_must_match_initial_worktree_identity(self):
        path = evidence.SCENARIO_FIXTURE.as_posix()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence'
            with mock.patch.object(sys, 'argv', ['evidence', '--output', str(output), '--run-local', 'corpus']), \
                    mock.patch.object(evidence, 'implementation_identity', return_value={'files': {path: 'other digest'}}), \
                    mock.patch.object(evidence, 'run_local') as run, self.assertRaisesRegex(ValueError, 'fixture digest'):
                evidence.main()
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_execution_requires_one_named_test(self):
        summary = 'test result: ok. 1 passed; 0 failed; 0 ignored;'
        for text, expected in (('test wanted ... ok\n' + summary, 'PASS'),
                               ('test other ... ok\n' + summary, 'NOT_EXECUTED'),
                               (summary.replace('1 passed', '0 passed'), 'NOT_EXECUTED'),
                               ('test wanted ... ok\n' + summary + '\n' + summary, 'NOT_EXECUTED'),
                               ('test result: ok. 0 passed; 0 failed; 1 ignored;', 'SKIP')):
            with self.subTest(text=text):
                self.assertEqual(evidence.local_verdict(0, text, 'wanted')[0], expected)
        self.assertEqual(evidence.local_verdict(101, 'test wanted ... ok\n' + summary, 'wanted')[0], 'FAIL')

    def test_local_command_is_locked_exact_and_hashes_the_observed_log(self):
        for lane, target, test in [('corpus', 'syntra-runtime --test conformance_runner', 'sc_wire_vectors_decode'),
                                   ('echo', 'syntra-runtime --test conformance_runner', 'sc_echo'),
                                   ('native-tls13', 'syntra-net --features tls-rustls --test wss',
                                    'wss_server_rejects_tls12_client_before_authentication')]:
            log = f'test {test} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'

            def cargo(command, **kwargs):
                kwargs['stdout'].write(log)
                return subprocess.CompletedProcess(command, 0)

            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(evidence.subprocess, 'run', side_effect=cargo) as run:
                row = evidence.run_local(lane, Path(directory))
                self.assertEqual((row['verdict'], row['exit_code'], row['formal_conformance']), ('PASS', 0, False))
                command, = run.call_args.args
                self.assertEqual(command, ['cargo', 'test', '--locked', '--no-default-features', '-p', *target.split(),
                                           test, '--', '--exact', '--show-output', '--color', 'never'])
                self.assertEqual(row['command'], command)
                self.assertEqual(run.call_args.kwargs['cwd'], evidence.ROOT)
                self.assertEqual(run.call_args.kwargs['env']['RUSTUP_TOOLCHAIN'], '1.89.0')
                self.assertEqual(run.call_args.kwargs['stderr'], subprocess.STDOUT)
                self.assertEqual((Path(directory) / row['artifact']).read_bytes(), log.encode())
                self.assertEqual(row['artifact_sha256'], evidence.digest(log.encode()))

    def test_local_missing_tool_and_timeout_are_not_executed(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired(['cargo'], 300)):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(evidence.subprocess, 'run', side_effect=error):
                row = evidence.run_local('corpus', Path(directory))
                self.assertEqual(row['verdict'], 'NOT_EXECUTED')
                self.assertIn(type(error).__name__, row['reason'])
                self.assertNotIn('exit_code', row)

    def test_stdout_report_uses_current_contract_and_gates(self):
        scope = {'protocol': 'Syntra 1.0', 'carriers': ['SYNTRA-1.0-TCP', 'SYNTRA-1.0-WS', 'SYNTRA-1.0-WSS'],
                 'contexts': 9, 'negative_recipes': 36}
        with mock.patch.object(sys, 'argv', ['evidence']), contextlib.redirect_stdout(io.StringIO()) as stdout, \
                mock.patch.object(evidence, 'verify_protocol', return_value=scope), \
                mock.patch.object(evidence, 'implementation_identity', return_value=self.identity):
            self.assertEqual(evidence.main(), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report['format_version'], 3)
        self.assertEqual(report['kind'], 'implementation_evidence_not_conformance_declaration')
        self.assertFalse(report['formal_conformance_claimed'])
        self.assertEqual(report['implementation_wire_contract'], evidence.IMPLEMENTATION_WIRE_CONTRACT)
        self.assertEqual(report['scope'], scope)
        self.assertEqual(report['implementation']['before'], self.identity)
        self.assertEqual(report['implementation']['after'], self.identity)
        self.assertEqual(report['supplemental_results'], [])
        self.assertEqual(report['fixture_verification'], evidence.verify_transcriptions())
        self.assertFalse(report['worktree_changed_during_run'])
        self.assertEqual(report['worktree_changed_files'], [])
        self.assertEqual(set(report['external_gates']), {'formal_conformance', 'physical_ios_android', 'browser',
                         'direct_host_tls13_wss', 'independent_noise_vectors', 'device_budgets_and_soak',
                         'independent_security_review'})
        self.assertTrue(all(row['verdict'] == 'NOT_EXECUTED' and row['reason'] for row in report['external_gates'].values()))
        self.assertTrue({'formal_summary', 'results', 'suite_schema_issues', 'contract_alignment',
                         'candidate_agreement', 'pins'}.isdisjoint(report))

    def test_drift_without_requested_lanes_still_fails(self):
        after = {'files': {**self.identity['files'], 'new': 'digest'}}
        with mock.patch.object(sys, 'argv', ['evidence']), contextlib.redirect_stdout(io.StringIO()) as stdout, \
                mock.patch.object(evidence, 'verify_protocol', return_value={}), \
                mock.patch.object(evidence, 'implementation_identity', side_effect=[self.identity, after]):
            self.assertEqual(evidence.main(), 1)
        report = json.loads(stdout.getvalue())
        self.assertTrue(report['worktree_changed_during_run'])
        self.assertEqual(report['worktree_changed_files'], ['new'])

    def test_changed_worktree_or_unsuccessful_lane_invalidates_report(self):
        files = self.identity['files']
        for changed, verdict, expected in [(False, 'PASS', 0), (True, 'PASS', 1), (False, 'SKIP', 1),
                                           (False, 'FAIL', 1), (False, 'NOT_EXECUTED', 1)]:
            with self.subTest(changed=changed, verdict=verdict), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'evidence'
                args = ['evidence', '--output', str(output), '--run-local', 'corpus', '--run-local', 'corpus']
                with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        mock.patch.object(evidence, 'verify_protocol', return_value={}), \
                        mock.patch.object(evidence, 'implementation_identity', side_effect=[{'files': files}, {'files': {**files, 'x': 1} if changed else files}]), \
                        mock.patch.object(evidence, 'run_local', return_value={'verdict': verdict}) as run:
                    self.assertEqual(evidence.main(), expected)
                run.assert_called_once_with('corpus', output)
                report = json.loads((output / 'report.json').read_text())
                summary = json.loads(stdout.getvalue())
                self.assertEqual(summary, {'artifact': str(output / 'report.json'), 'kind': report['kind'],
                                           'formal_conformance_claimed': False, 'supplemental_results': report['supplemental_results']})
                self.assertFalse(report['formal_conformance_claimed'])
                self.assertEqual(report['external_gates']['formal_conformance']['verdict'], 'NOT_EXECUTED')
                self.assertEqual(report['worktree_changed_files'], ['x'] if changed else [])
                self.assertEqual(report['supplemental_results'][0]['verdict'], 'NOT_EXECUTED' if changed else verdict)

    def test_cli_refuses_removed_options_and_requires_output_for_lanes(self):
        for args in (['--execute'], ['--profile', 'x'], ['--upstream', '.'], ['--candidate-agreement', 'offline'],
                     ['--run-local', 'corpus']):
            with self.subTest(args=args), mock.patch.object(sys, 'argv', ['evidence', *args]), \
                    contextlib.redirect_stderr(io.StringIO()), mock.patch.object(evidence, 'implementation_identity') as identity, \
                    self.assertRaises(SystemExit) as error:
                evidence.main()
            self.assertEqual(error.exception.code, 2)
            identity.assert_not_called()

    def test_existing_symlink_and_inside_worktree_outputs_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'link'
            link.symlink_to(Path(directory) / 'missing')
            for path, reason in ((directory, 'new directory'), (link, 'new directory'),
                                 (evidence.ROOT / 'invalid-evidence-output', 'outside the implementation worktree')):
                with self.subTest(path=path), mock.patch.object(sys, 'argv', ['evidence', '--output', str(path)]), \
                        self.assertRaisesRegex(ValueError, reason):
                    evidence.main()
