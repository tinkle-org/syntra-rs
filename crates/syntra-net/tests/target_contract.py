"""Check feature entry points, real regression execution and the wasm32 boundary.

Run from the repository root with Python 3 and its Rust toolchain active:
python3 crates/syntra-net/tests/target_contract.py
The wasm32-unknown-unknown Rust target must be installed.
"""

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
FEATURES = ("tcp", "http", "websocket", "tls-rustls", "reconnect", "managed", "proxy", "native-enrollment", "cross-carrier-candidate")
REGRESSIONS = (
    ("http", ("--test", "http_records")),
    ("http", ("--test", "http_connections")),
    ("http", ("--lib", "http::")),
    ("websocket", ("--test", "tls_provider")),
    ("tls-rustls", ("--test", "wss")),
    ("tls-rustls,reconnect", ("--test", "recovery_wss")),
    ("managed", ("--test", "network")),
    ("managed", ("--lib", "network::tests::")),
    ("proxy", ("--test", "proxy")),
    ("managed,websocket,proxy", ("--test", "network_websocket")),
    ("managed,websocket,proxy", ("--lib", "network::tests::")),
    ("managed,websocket,proxy", ("--test", "routes")),
    ("managed,tls-rustls,proxy", ("--test", "network_websocket")),
    ("managed,tls-rustls,proxy", ("--test", "routes")),
    ("managed,http,proxy", ("--test", "http_connections")),
    ("managed,http,proxy", ("--test", "network_http")),
    ("managed,http,proxy", ("--test", "routes")),
    ("managed,http,websocket,proxy", ("--test", "http_connections")),
    ("managed,http,websocket,proxy", ("--test", "network_http")),
    ("managed,http,websocket,proxy", ("--test", "routes")),
    ("managed", ("--example", "managed_tcp")),
    ("managed,websocket", ("--example", "managed_wss")),
    ("managed,http", ("--example", "managed_http")),
)
CROSS_CARRIER_REGRESSIONS = (
    ("managed,websocket,proxy,cross-carrier-candidate", ("--test", "cross_carrier")),
    ("managed,websocket,proxy,cross-carrier-candidate", ("--test", "routes")),
    ("managed,http,websocket,proxy,cross-carrier-candidate", ("--test", "cross_carrier")),
    ("managed,http,websocket,proxy,cross-carrier-candidate", ("--test", "routes")),
)
CROSS_CARRIER_TESTS = (
    "policy_has_no_implicit_permissions_and_rejects_duplicates_and_local_ws",
    "entire_routes_and_unused_allowlist_keep_bounds_and_endpoint_validation",
    "unpolled_is_inert_and_selected_endpoints_are_round_robin_with_unchanged_errors",
    "selected_carrier_mismatch_is_not_rewritten_or_dialed",
    "expired_supplied_or_shortened_route_budget_precedes_selection_and_inputs",
    "scope_callback_overrun_of_supplied_or_shortened_deadline_emits_no_socket_io",
    "mixed_candidate_validates_unused_permissions_and_old_api_stays_homogeneous",
    "mixed_selection_is_inert_until_polled_and_mismatch_precedes_provider_and_dial",
    "input_callback_does_not_hold_route_selection_lock",
    "supervised::automatic_tcp_to_provider_wss_and_back_both_authentication_modes",
    "supervised::live_tcp_wss_tcp_generations_use_fresh_endpoint_inputs_both_modes",
    "supervised::terminal_input_failure_leaves_successor_untouched",
    "supervised::terminal_real_tls_failure_does_not_select_tcp_successor",
    "supervised::terminal_noise_failure_does_not_select_provider_wss_successor",
)
CROSS_CARRIER_HTTP_TESTS = (
    "supervised::automatic_tcp_to_real_provider_https_both_authentication_modes",
)
CANDIDATE_BUDGET_FEATURES = "managed,http,websocket,proxy,cross-carrier-candidate"
CANDIDATE_BUDGET_SECURITY_TESTS = (
    "client::tests::http_recovery::recovery_http_partial_write_keeps_owner_cutoff_on_both_streams",
    "client::tests::http_recovery::ordinary_and_recovery_http_release_setup_only_at_their_readiness_boundary",
    "client::tests::http_recovery::cancelling_required_http_recovery_keeps_gate_closed_to_application_calls",
    "client::tests::synchronous_budget_factory_overrun_emits_no_socket_bytes",
    "client::tests::parent_outage_budget_gates_every_raw_poll_within_one_write",
    "pump::tests::deferred_completion_keeps_cutoff_through_core_ready_and_drop",
    "pump::tests::ordinary_core_ready_still_releases_the_attempt_gate",
    "pump::tests::absolute_budget_adoption_keeps_cutoff_and_rejects_expiry_and_continuity_loss",
    "pump::tests::capped_budget_preserves_origin_clock_and_every_earlier_gate",
    "websocket::tests::active_loss::protected_ws_active_eof_retries_with_ordinary_supervisor",
    "websocket::tests::active_loss::protected_provider_wss_active_eof_retries_with_ordinary_supervisor",
    "websocket::tests::active_loss::protected_ws_malformed_frame_blocks_ordinary_supervisor",
    "websocket::tests::active_loss::protected_provider_wss_malformed_frame_blocks_ordinary_supervisor",
)
MANAGED_SHUTDOWN_TESTS = (
    "client::tests::close_outcome_distinguishes_pending_waits_from_joined_errors",
    "client::tests::close_timeout_and_cancelled_close_retain_the_owner_join",
    "client::tests::local_pump_panic_stops_replacement_and_keeps_shutdown_failure_visible",
    "client::tests::managed_joined_pump_failure_is_reported_once",
    "client::tests::managed_healthy_close_has_no_failure",
    "client::tests::managed_pending_close_wait_is_not_reported_as_failure",
    "network::tests::ordinary_and_budget_clients_share_registration_controls_and_owned_shutdown",
)
TERMINAL_RECEIPT_GAP_TESTS = (
    "sibling_completion_during_owned_commit_gap_has_no_delivery_permission",
    "owned_commit_gap_exact_freshness_expiry_cannot_be_revived",
)
HTTP_PROXY_TESTS = (
    "candidate::proxied::socks_connect_and_real_forward_http_https_encrypted_rpc_both_modes",
    "candidate::proxied::proxy_target_authority_kind_allowlist_and_debug_are_checked_before_inputs",
    "candidate::proxied::real_forward_open_shares_setup_budget_and_cancel_closes_both_lanes",
)
CORE_CONTEXT_TESTS = {
    None: ("exact_raw_rfc0013_source_sha256_and_inventory",
           "default_rejects_all_four_candidate_rows_even_with_source_present"),
    "http-candidate": ("exact_raw_rfc0013_source_sha256_and_inventory",
                       "candidate::four_golden_contexts_encode_parse_and_first_flight",
                       "candidate::exact_golden_context_is_entire_noise_prologue_for_both_roles"),
}
WASM = "wasm32-unknown-unknown"
NATIVE_ONLY = (
    "require a non-wasm32 target; disable these features for wasm32 and "
    "compose syntra-core and syntra-runtime with platform I/O"
)


def check(*arguments):
    return subprocess.run(
        ["cargo", "check", "--locked", "-p", "syntra-net", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


class TargetContract(unittest.TestCase):
    def test_terminal_receipt_gap_regressions_execute_exactly(self):
        """Require both synchronized commit-gap cases to execute in TCP feature graphs."""
        for features in ("tcp", "tcp,websocket"):
            for test in TERMINAL_RECEIPT_GAP_TESTS:
                with self.subTest(features=features, test=test):
                    command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                               "--features", features, "--test", "terminal_receipt", test,
                               "--", "--exact", "--color", "never"]
                    print("$ " + " ".join(command), flush=True)
                    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                            timeout=300, check=False)
                    output = result.stdout + result.stderr
                    print(output, end="", flush=True)
                    self.assertEqual(result.returncode, 0, output)
                    self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)
                    self.assertIn("test result: ok. 1 passed; 0 failed; 0 ignored;", output)

    def test_managed_shutdown_regressions_execute_exactly(self):
        for test in MANAGED_SHUTDOWN_TESTS:
            with self.subTest(test=test):
                command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                           "--features", "managed", "--lib", test,
                           "--", "--exact", "--color", "never"]
                print("$ " + " ".join(command), flush=True)
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                        timeout=300, check=False)
                output = result.stdout + result.stderr
                print(output, end="", flush=True)
                self.assertEqual(result.returncode, 0, output)
                self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)
                self.assertIn("test result: ok. 1 passed; 0 failed; 0 ignored;", output)

    def test_candidate_budget_security_regressions_execute_exactly(self):
        # These library tests are not selected by the integration-test targets.
        for test in CANDIDATE_BUDGET_SECURITY_TESTS:
            with self.subTest(test=test):
                command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                           "--features", CANDIDATE_BUDGET_FEATURES, "--lib", test,
                           "--", "--exact", "--color", "never"]
                print("$ " + " ".join(command), flush=True)
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                        timeout=300, check=False)
                output = result.stdout + result.stderr
                print(output, end="", flush=True)
                self.assertEqual(result.returncode, 0, output)
                self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)
                self.assertIn("test result: ok. 1 passed; 0 failed; 0 ignored;", output)

    def test_candidate_failover_example_executes(self):
        command = ["cargo", "run", "--locked", "-p", "syntra-net", "--no-default-features",
                   "--features", "managed,websocket,cross-carrier-candidate",
                   "--example", "managed_wss", "--", "--failover"]
        print("$ " + " ".join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                timeout=300, check=False)
        print(result.stdout + result.stderr, end="", flush=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = result.stdout
        self.assertEqual(re.findall(r"(?m)^Candidate attempt carrier: (\S+)$", output),
                         ["Tcp", "SecureWebSocket"], output)
        self.assertIn("Candidate fallback ready: WSS after TCP timeout (not recovery readiness)", output)
        ready = re.search(r"(?m)^CoreReady: generation ([1-9][0-9]*)$", output)
        if ready is None:
            self.fail(output)
        self.assertIn(f"Echo OK: 16 bytes in generation {ready[1]}", output)
        self.assertIn("Network shutdown: ShutdownReport { complete: true, pending_operations: 0, failed_supervisors: 0 }", output)

    def test_cross_carrier_candidate_regressions_execute(self):
        # Exercise the opt-in API and keep the legacy routes API same-carrier
        # even when the candidate feature is unified into the test graph.
        for features, selection in CROSS_CARRIER_REGRESSIONS:
            with self.subTest(features=features, selection=selection):
                command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                           "--features", features, *selection, "--", "--color", "never"]
                print("$ " + " ".join(command), flush=True)
                result = subprocess.run(
                    command,
                    cwd=ROOT, text=True, capture_output=True, timeout=300, check=False,
                )
                output = result.stdout + result.stderr
                print(output, end="", flush=True)
                self.assertEqual(result.returncode, 0, output)
                self.assertRegex(output, r"(?m)^test \S+ \.\.\. ok$",
                                 "candidate target did not report a named passing test: " + output)
                self.assertRegex(output, r"test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored;",
                                 "candidate target must execute nonzero passing, non-ignored tests: " + output)
                if selection == ("--test", "cross_carrier"):
                    expected = CROSS_CARRIER_TESTS
                    if "http" in features.split(","):
                        expected += CROSS_CARRIER_HTTP_TESTS
                    for test in expected:
                        self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)

    def test_http_proxy_regressions_execute_exactly(self):
        for features in ("managed,http,proxy", "managed,http,websocket,proxy"):
            for test in HTTP_PROXY_TESTS:
                with self.subTest(features=features, test=test):
                    command = ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                               "--features", features, "--test", "routes", test,
                               "--", "--exact", "--color", "never"]
                    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                            timeout=300, check=False)
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0, output)
                    self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)
                    self.assertIn("test result: ok. 1 passed; 0 failed; 0 ignored;", output)

    def test_core_candidate_context_regressions_execute(self):
        for features, expected in CORE_CONTEXT_TESTS.items():
            with self.subTest(features=features):
                command = ["cargo", "test", "--locked", "-p", "syntra-core", "--no-default-features"]
                if features:
                    command += ["--features", features]
                command += ["--test", "http_candidate_context", "--", "--color", "never"]
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                        timeout=300, check=False)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                self.assertRegex(output, r"test result: ok\. [1-9][0-9]* passed; 0 failed;", output)
                for test in expected:
                    self.assertRegex(output, rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)

    def test_wasm_core_candidate_compiles(self):
        result = subprocess.run(
            ["cargo", "check", "--locked", "-p", "syntra-core", "--no-default-features",
             "--features", "http-candidate", "--lib", "--target", WASM],
            cwd=ROOT, text=True, capture_output=True, timeout=300, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_feature_regressions_execute(self):
        for features, selection in REGRESSIONS:
            with self.subTest(features=features, selection=selection):
                result = subprocess.run(
                    ["cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                     "--features", features, *selection, "--", "--color", "never"],
                    cwd=ROOT, text=True, capture_output=True, timeout=300, check=False,
                )
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                self.assertRegex(output, r"test result: ok\. [1-9][0-9]* passed; 0 failed;",
                                 "feature target compiled but no tests executed: " + output)

    def test_native_features_compile_independently(self):
        for feature in FEATURES:
            with self.subTest(feature=feature):
                result = check("--all-targets", "--no-default-features", "--features", feature)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wasm_default_compiles_all_targets_without_native_exports(self):
        result = check("--target", WASM, "--all-targets")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wasm_native_features_report_the_actionable_boundary(self):
        for feature in (*FEATURES, ",".join(FEATURES)):
            with self.subTest(feature=feature):
                result = check("--target", WASM, "--lib", "--no-default-features", "--features", feature)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(NATIVE_ONLY, output)
                diagnostic = re.search(r"syntra-net features (.*?) require a non-wasm32 target;", output)
                if diagnostic is None:
                    self.fail(output)
                for native in FEATURES:
                    self.assertIn(native, diagnostic[1], "diagnostic must name every native-only feature")
                self.assertNotIn("error[E", output, "unexpected Rust type or import error")


if __name__ == "__main__":
    unittest.main()
