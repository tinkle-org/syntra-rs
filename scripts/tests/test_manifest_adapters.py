"""Negative execution/identity/observation tests for local supplemental scenarios."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import conformance_evidence as evidence
import manifest_adapters as adapters
from upstream_snapshot import digest


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.request = adapters.request_for("wss-unknown-field")

    def result(self, request=None):
        request = request or self.request
        return {**{key: request[key] for key in (
                    "protocol", "kind", "formal_conformance", "nonce", "scenario_id",
                    "scenario_sha256", "role", "carrier_id")},
                "carrier": {"tls": "1.3", "termination": "direct_host", "noise_mode": "bootstrap",
                            "wire": "Syntra1.0/WSS", **adapters.IMPLEMENTATION_WIRE_CONTRACT},
                "observation": {"connection_state": "ACTIVE", "session_state": "unchanged",
                    "frames": [{"request_id": 7, "body": "result", "payload_hex": "6869"}],
                    "sent_frames_hex": ["setup", *request["frames_hex"], "followup"],
                    "checks": {"followup_usable_same_session": True}}}

    def test_only_local_current_scenarios_are_selectable(self):
        for identifier in adapters.SUPPLEMENTAL_SCENARIOS:
            request = adapters.request_for(identifier)
            self.assertEqual(request["protocol"], 2)
            self.assertEqual(request["carrier_id"], "SYNTRA-1.0-WSS")
            self.assertEqual(request["kind"], "supplemental_local_scenario")
            self.assertFalse(request["formal_conformance"])
            self.assertNotIn("case_id", request)
            self.assertNotIn("case_sha256", request)
            self.assertNotIn("suite_revision", request)
            self.assertEqual(request["scenario_sha256"], digest(adapters.canonical(request["scenario"])))
        for identifier in ("invalid-token", "not-a-scenario"):
            with self.assertRaisesRegex(ValueError, "unknown supplemental"):
                adapters.request_for(identifier)
        self.assertFalse(hasattr(adapters, "execute_case"))
        self.assertFalse(hasattr(adapters, "CASE_PINS"))

    def test_observations_not_exit_status_are_the_oracle(self):
        adapters.validate_result(self.request, self.result())
        for path, value in [(('observation', 'frames'), []),
                            (('observation', 'frames', 0, 'payload_hex'), 'ff'),
                            (('observation', 'frames', 0, 'request_id'), 99),
                            (('observation', 'connection_state'), 'CLOSED'),
                            (('observation', 'session_state'), 'active'),
                            (('observation', 'sent_frames_hex'), ['setup', 'wrong']),
                            (('observation', 'checks'), {}),
                            (('carrier', 'tls'), '1.2'),
                            (('carrier', 'subprotocol'), 'invalid-token'),
                            (('carrier_id',), 'invalid-token'),
                            (('protocol',), 1),
                            (('nonce',), 'old-run'), (('scenario_sha256',), 'old-input'),
                            (('kind',), 'formal'), (('formal_conformance',), True)]:
            result = self.result()
            target = result
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises((ValueError, KeyError)):
                adapters.validate_result(self.request, result)

    def test_missing_observation_fields_never_pass(self):
        for field in self.result()['observation']:
            result = self.result()
            del result['observation'][field]
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                adapters.validate_result(self.request, result)

    def test_missing_carrier_identity_never_passes(self):
        result = self.result()
        del result['carrier_id']
        with self.assertRaisesRegex(ValueError, 'carrier_id'):
            adapters.validate_result(self.request, result)

    def test_input_identity_covers_faults_controls_and_assertions(self):
        for field in ('input', 'expected', 'control_connection', 'notes'):
            scenario = copy.deepcopy(self.request['scenario'])
            scenario[field] = {'changed': True}
            self.assertNotEqual(digest(adapters.canonical(scenario)), self.request['scenario_sha256'])
        self.assertNotEqual(adapters.request_for('wss-unknown-field')['nonce'], self.request['nonce'])

    def test_declared_assertions_without_an_oracle_are_refused(self):
        scenario = copy.deepcopy(self.request['scenario'])
        scenario['expected']['transport'] = {'must_be_observed': True}
        with mock.patch.object(adapters, 'scenario_for', return_value=scenario):
            with self.assertRaisesRegex(ValueError, 'lacks an oracle'):
                adapters.request_for('wss-unknown-field')

    def test_fixture_encoder_preserves_unknown_field_and_empty_selection(self):
        frame = self.request['scenario']['input']['frames'][0]
        self.assertTrue(adapters.frame_bytes(frame).endswith(bytes.fromhex('d2050178')))
        frame = {**frame, 'payload_b64': '', 'unknown_fields': []}
        self.assertIn(bytes.fromhex('1200'), adapters.frame_bytes(frame))
        no_timeout = {key: value for key, value in frame.items() if key != 'timeout_ms'}
        self.assertEqual(adapters.frame_bytes(no_timeout), adapters.frame_bytes({**frame, 'timeout_ms': 0}))
        with self.assertRaises(ValueError):
            adapters.frame_bytes({**frame, 'unreviewed': True})

    def run_fake(self, text, returncode=0, artifact=True, tamper=None):
        def run(command, **kwargs):
            for arg in ('--exact', '--ignored', 'websocket,native-enrollment', 'syntra-transport', 'supplemental_scenario'):
                self.assertIn(arg, command)
            self.assertEqual(kwargs['env']['RUSTUP_TOOLCHAIN'], '1.88.0')
            request = json.loads(Path(kwargs['env']['SYNTRA_SUPPLEMENTAL_REQUEST']).read_text())
            if artifact:
                result = self.result(request)
                if tamper:
                    tamper(result)
                Path(kwargs['env']['SYNTRA_SUPPLEMENTAL_RESULT']).write_text(json.dumps(result))
            kwargs['stdout'].write(text)
            return subprocess.CompletedProcess(command, returncode)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapters.subprocess, 'run', side_effect=run):
            row = evidence.run_local('wss-unknown-field', Path(directory))
            self.assertGreaterEqual(len(row['execution']['artifacts']), 2)
            self.assertFalse(row['formal_conformance'])
            self.assertNotIn('test_id', row)
            self.assertNotIn('case_sha256', row)
            return row

    def test_exact_executed_test_plus_valid_fresh_observations_passes_supplementally(self):
        row = self.run_fake('test supplemental_scenario ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;')
        self.assertEqual(row['verdict'], 'PASS')
        self.assertTrue(row['executed'])

    def test_zero_ignored_wrong_test_or_missing_proof_never_pass(self):
        for text in ['test result: ok. 0 passed; 0 failed; 0 ignored;',
                     'test result: ok. 0 passed; 0 failed; 1 ignored;',
                     'test wrong ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;', '']:
            self.assertEqual(self.run_fake(text)['verdict'], 'NOT_EXECUTED')

    def test_successful_cargo_without_artifact_or_with_bad_observations_fails(self):
        text = 'test supplemental_scenario ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
        self.assertEqual(self.run_fake(text, artifact=False)['verdict'], 'FAIL')
        for tamper in (lambda r: r.update(nonce='stale'),
                       lambda r: r['observation']['frames'][0].update(payload_hex='ff'),
                       lambda r: r['observation']['frames'][0].update(request_id=99),
                       lambda r: r['observation'].pop('checks')):
            self.assertEqual(self.run_fake(text, tamper=tamper)['verdict'], 'FAIL')

    def test_existing_artifacts_are_never_reused(self):
        for suffix in ('request.json', 'observed.json', 'log'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(adapters.subprocess, 'run') as run:
                path = Path(directory) / ('local-wss-unknown-field.' + suffix)
                path.write_text('stale')
                with self.assertRaises(FileExistsError):
                    evidence.run_local('wss-unknown-field', Path(directory))
                self.assertEqual(path.read_text(), 'stale')
                run.assert_not_called()

    def test_symlink_observation_cannot_supply_execution_proof(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapters.subprocess, 'run') as run:
            path = Path(directory) / 'local-wss-unknown-field.observed.json'
            path.symlink_to(Path(directory) / 'missing')
            with self.assertRaises(FileExistsError):
                evidence.run_local('wss-unknown-field', Path(directory))
            run.assert_not_called()

    def test_compile_failure_is_not_scenario_behavior_failure(self):
        self.assertEqual(self.run_fake('error: compilation failed', 101, False)['verdict'], 'NOT_EXECUTED')
        row = self.run_fake('test supplemental_scenario ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;', 101, False)
        self.assertEqual(row['verdict'], 'FAIL')
        self.assertTrue(row['executed'])

    def test_duplicate_requires_local_cause_no_frames_and_held_terminal_barrier(self):
        request = adapters.request_for('wss-duplicate-id')
        result = self.result(request)
        result['observation'].update(connection_state='CLOSED', session_state='terminated_abnormally', frames=[],
            error={'code': 'FAILED_PRECONDITION', 'observer': 'detecting_host', 'carriage': 'local_only'},
            checks={'first_handler_started': True, 'held_until_violation_and_closure': True,
                    'offending_dispatches': 0, 'peer_transport_closed': True, 'peer_success_results': 0})
        adapters.validate_result(request, result)
        for key, value in result['observation']['checks'].items():
            broken = copy.deepcopy(result)
            broken['observation']['checks'][key] = not value if isinstance(value, bool) else 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapters.validate_result(request, broken)
        broken = copy.deepcopy(result)
        broken['observation']['error']['observer'] = 'peer'
        with self.assertRaises(ValueError):
            adapters.validate_result(request, broken)

    def test_deadline_requires_actual_delay_and_bounded_correlated_terminal(self):
        request = adapters.request_for('wss-deadline')
        result = self.result(request)
        result['observation']['frames'] = [{'request_id': 9, 'body': 'result', 'error': {'code': 'DEADLINE_EXCEEDED'}}]
        result['observation']['checks'].update(handler_delay_ms=1000, terminal_elapsed_ms=101,
            completed_handlers_at_terminal=0, dispatched_handlers=1)
        adapters.validate_result(request, result)
        for key, value in [('handler_delay_ms', 0), ('terminal_elapsed_ms', 0), ('terminal_elapsed_ms', 700),
                           ('completed_handlers_at_terminal', 1), ('dispatched_handlers', 0)]:
            broken = copy.deepcopy(result)
            broken['observation']['checks'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapters.validate_result(request, broken)
        broken = copy.deepcopy(result)
        broken['observation']['frames'][0]['request_id'] = 99
        with self.assertRaisesRegex(ValueError, 'not correlated'):
            adapters.validate_result(request, broken)

    def test_16_rpc_floor_requires_all_admitted_before_reverse_release(self):
        request = adapters.request_for('wss-reverse-completion')
        result = self.result(request)
        result['observation']['frames'] = [{'request_id': row['request_id'], 'body': 'result',
            'payload_hex': bytes([row['request_id']]).hex()} for row in request['scenario']['expected']['frames']]
        result['observation']['checks'].update(all_admitted_before_release=16, completed_before_release=0,
                                              release_order=list(range(36, 20, -1)))
        adapters.validate_result(request, result)
        for key, value in [('all_admitted_before_release', 15), ('completed_before_release', 1),
                           ('release_order', list(range(21, 37)))]:
            broken = copy.deepcopy(result)
            broken['observation']['checks'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapters.validate_result(request, broken)

    def test_recovery_requires_paired_control_exact_bounds_and_reprobe_isolation(self):
        request = adapters.request_for('wss-recovery-isolation')
        result = self.result(request)
        got = result['observation']
        got['frames'] = [{'request_id': 3, 'body': 'result', 'error': {'code': 'UNIMPLEMENTED'}}]
        got['checks'].update(same_service_principal_scope_selector=True, distinct_connections=True,
            unconfirmed_captures=0, control_captures=1, probe_after_control={'error': {'code': 'UNIMPLEMENTED'}})
        got['control_connection'] = {'connection_state': 'ACTIVE', 'session_state': 'unchanged',
            'sent_frames_hex': ['setup', *request['control_frames_hex']],
            'frames': [{'request_id': 1, 'body': 'result', 'shape': 'RecoveryNegotiateResponse', 'decoded': {
                'profile_version': 1, 'selected_version': 1, 'max_subscriptions_per_connection': 64,
                'max_pending_rpcs_per_connection': 16, 'max_page_bytes': 262144, 'max_snapshot_pages': 256}},
                {'request_id': 3, 'body': 'result', 'shape': 'RecoverySubscribeResponse', 'decoded': {
                    'profile_version': 1, 'generation': 7, 'subscription_handle_hex': 'abcd',
                    'catchup_boundary_hex': b'boundary-A'.hex()}}]}
        adapters.validate_result(request, result)
        for key, value in [('unconfirmed_captures', 1), ('control_captures', 0), ('distinct_connections', False),
                           ('probe_after_control', {'error': {'code': 'FAILED_PRECONDITION'}})]:
            broken = copy.deepcopy(result)
            broken['observation']['checks'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                adapters.validate_result(request, broken)
        broken = copy.deepcopy(result)
        del broken['observation']['control_connection']
        with self.assertRaises(KeyError):
            adapters.validate_result(request, broken)
        broken = copy.deepcopy(result)
        broken['observation']['control_connection']['frames'][0]['decoded']['selected_version'] = 2
        with self.assertRaises(ValueError):
            adapters.validate_result(request, broken)


class LiveExecutionProtocolTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SYNTRA_LIVE_ADAPTER_PROTOCOL') == '1',
                         'opt-in real Cargo execution protocol check (native-enrollment graph)')
    def test_real_zero_ignored_and_single_test_proofs(self):
        prefix = ['cargo', 'test', '--locked', '-p', 'syntra-transport', '--no-default-features',
                  '--features', 'websocket,native-enrollment', '--test', 'manifest_cases']
        for name, expected in [('_no_such_supplemental_scenario_', 'NOT_EXECUTED'),
                               ('supplemental_scenario', 'SKIP'),
                               ('supplemental_error_vocabulary', 'PASS')]:
            command = [*prefix, name, '--', '--exact', '--show-output', '--color', 'never']
            completed = subprocess.run(command, cwd=adapters.ROOT, check=True, capture_output=True,
                                       text=True, timeout=180, env={**os.environ, 'RUSTUP_TOOLCHAIN': '1.88.0'})
            proof, _ = evidence.local_verdict(completed.returncode, completed.stdout, name)
            with self.subTest(test=name):
                self.assertEqual(proof, expected)


class LifecycleScopeTests(unittest.TestCase):
    def test_partial_enrollment_probes_remain_supplemental(self):
        for lane, name in evidence.NATIVE_LOCAL_LANES.items():
            def run(command, **kwargs):
                self.assertIn('websocket,native-enrollment', command)
                self.assertIn('--lib', command)
                self.assertIn('--no-default-features', command)
                kwargs['stdout'].write(f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;')
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(evidence.subprocess, 'run', side_effect=run):
                result = evidence.run_local(lane, Path(directory))
            self.assertEqual(result['verdict'], 'PASS')
            self.assertFalse(result['formal_conformance'])
            self.assertNotIn('test_id', result)


if __name__ == '__main__':
    unittest.main()
