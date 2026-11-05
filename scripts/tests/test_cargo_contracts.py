"""Default graph checks must not confuse dev/test dependencies with production."""

import json
from pathlib import Path
import runpy
import subprocess
import sys
import tomllib
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cargo_contracts as contracts


class DependencyIsolationTests(unittest.TestCase):
    def test_minimal_default_graph(self):
        graph = "syntra-runtime v1.0.0 (/repo)|\ntokio v1.0.0|macros,rt,sync,time\nlibc v0.2.0|default,std (*)\n"
        self.assertEqual(contracts.graph_violations(graph, "syntra-runtime"), [])

    def test_network_tls_ws_sqlite_and_file_store_are_rejected(self):
        for dependency in ("mio", "socket2", "http", "http-body", "httparse", "h2", "hyper", "reqwest", "quinn",
                           "ws_stream_wasm", "rustls", "rustls-webpki", "tokio-rustls", "native-tls",
                           "tokio-tungstenite", "tungstenite", "rusqlite", "libsqlite3-sys", "sqlx-sqlite", "fs2"):
            with self.subTest(dependency=dependency):
                graph = f"syntra-runtime v1.0.0|\n{dependency} v0.1.0|default\n"
                self.assertTrue(contracts.graph_violations(graph, "syntra-runtime"))

    def test_forbidden_features_cannot_hide_behind_allowed_package(self):
        for dependency, features in contracts.FORBIDDEN_FEATURES.items():
            for feature in features:
                with self.subTest(dependency=dependency, feature=feature):
                    graph = f"syntra-core v1.0.0|\n{dependency} v1.0.0|default,{feature}\n"
                    self.assertTrue(contracts.graph_violations(graph, "syntra-core"))

    def test_empty_wrong_or_unrecognized_graph_never_passes(self):
        for graph in ("", "tokio v1.0.0|sync\n", "syntra-runtime (unparsed)"):
            with self.subTest(graph=graph), self.assertRaises(ValueError):
                contracts.graph_violations(graph, "syntra-runtime")

    def test_isolation_uses_each_default_root_without_dev_or_workspace_unification(self):
        self.assertEqual(contracts.ISOLATED_PACKAGES, ("syntra-core", "syntra-runtime", "syntra-net"))
        def cargo(command, root):
            self.assertEqual(command[:2], ["tree", "--locked"])
            self.assertEqual(command[command.index("--edges") + 1], "normal,build")
            self.assertNotIn("--no-default-features", command)
            self.assertNotIn("--workspace", command)
            self.assertNotIn("--features", command)
            package = command[command.index("-p") + 1]
            return subprocess.CompletedProcess(command, 0, f"{package} v1.0.0|\n")
        with mock.patch.object(contracts, "workspace_packages", return_value=dict.fromkeys(contracts.ISOLATED_PACKAGES)), \
                mock.patch.object(contracts, "cargo", side_effect=cargo) as run, mock.patch("builtins.print"):
            contracts.isolation()
        self.assertEqual(run.call_count, 6)
        self.assertEqual(
            {(call.args[0][call.args[0].index("-p") + 1],
              call.args[0][call.args[0].index("--target") + 1] if "--target" in call.args[0] else "host")
             for call in run.call_args_list},
            {(package, target) for package in contracts.ISOLATED_PACKAGES
             for target in ("host", "wasm32-unknown-unknown")},
        )

    def test_missing_renamed_package_is_alignment_failure_not_silent_skip(self):
        with mock.patch.object(contracts, "workspace_packages", return_value={}), self.assertRaisesRegex(ValueError, "package set is incomplete"):
            contracts.isolation()

    def test_websocket_graph_allows_framing_but_rejects_tls_packages_and_features(self):
        graph = "syntra-net v1.0.0|websocket\ntokio v1.0.0|net,io-util\ntokio-tungstenite v0.30.0|handshake\nhttp v1.0.0|std\nhttparse v1.10.1|std\n"
        self.assertEqual(contracts.graph_violations(graph, "syntra-net", no_tls_features={"websocket"}), [])
        for dependency in ("rustls", "rustls-native-certs", "rustls-webpki", "tokio-rustls",
                           "native-tls", "tokio-native-tls", "openssl-sys", "security-framework", "schannel", "webpki-roots"):
            with self.subTest(dependency=dependency):
                self.assertTrue(contracts.graph_violations(graph + f"{dependency} v0.1.0|\n", "syntra-net", no_tls_features={"websocket"}))
        for package, features in contracts.TLS_FEATURES.items():
            for feature in features:
                with self.subTest(package=package, feature=feature):
                    self.assertTrue(contracts.graph_violations(graph + f"{package} v1.0.0|{feature}\n", "syntra-net", no_tls_features={"websocket"}))

    def test_websocket_graph_requires_the_feature_and_excludes_dev_unification(self):
        with self.assertRaisesRegex(ValueError, "did not enable"):
            contracts.graph_violations("syntra-net v1.0.0|\n", "syntra-net", no_tls_features={"websocket"})
        with mock.patch.object(contracts, "cargo", return_value=subprocess.CompletedProcess([], 0, "syntra-net v1.0.0|websocket\n")) as cargo, \
                mock.patch("builtins.print"):
            contracts.websocket()
        command = cargo.call_args.args[0]
        self.assertEqual(command[command.index("--edges") + 1], "normal,build")
        self.assertEqual(command[command.index("--features") + 1], "websocket")
        self.assertIn("--no-default-features", command)
        self.assertNotIn("--workspace", command)

    def test_http_feature_unification_is_rejected_even_without_http_package(self):
        # The opt-in module uses Tokio/url, so its presence cannot be inferred
        # from the `http` package used by WebSocket framing.
        for features, expected in (("http", None), ("http,websocket", {"websocket"}),
                                   ("http,managed,websocket,proxy,tcp,reconnect",
                                    {"managed", "websocket", "proxy", "tcp", "reconnect"})):
            with self.subTest(features=features):
                violations = contracts.graph_violations(f"syntra-net v1.0.0|{features}\n", "syntra-net",
                                                       no_tls_features=expected)
                self.assertTrue(any("enables syntra-net/http" in value for value in violations))

    def test_cross_carrier_candidate_is_rejected_in_every_existing_lane(self):
        for features in (None, {"websocket"}, {"managed", "websocket", "proxy", "tcp", "reconnect"},
                         {"http"}, {"managed", "http", "proxy", "tcp", "reconnect"},
                         {"managed", "http", "websocket", "proxy", "tcp", "reconnect"}):
            graph = "syntra-net v1.0.0|" + ",".join(sorted((features or set()) | {"cross-carrier-candidate"})) + "\n"
            if features and "http" in features:
                graph += "syntra-core v1.0.0|http-candidate\n"
            with self.subTest(features=features):
                violations = contracts.graph_violations(graph, "syntra-net", no_tls_features=features)
                self.assertTrue(any("enables syntra-net/cross-carrier-candidate" in value for value in violations))

    def test_managed_websocket_graph_keeps_requested_features_but_rejects_tls(self):
        features = {"managed", "websocket", "proxy", "tcp", "reconnect"}
        graph = "syntra-net v1.0.0|managed,websocket,proxy,tcp,reconnect\ntokio v1.0.0|net,rt-multi-thread\n"
        self.assertEqual(contracts.graph_violations(graph, "syntra-net", no_tls_features=features), [])
        for extra in ("rustls v0.23.0|std\n", "syntra-net v1.0.0|tls-rustls\n",
                      "tokio-tungstenite v0.30.0|__rustls-tls\n"):
            with self.subTest(extra=extra):
                self.assertTrue(contracts.graph_violations(graph + extra, "syntra-net", no_tls_features=features))
        with self.assertRaisesRegex(ValueError, "did not enable"):
            contracts.graph_violations("syntra-net v1.0.0|websocket\n", "syntra-net", no_tls_features=features)
        with mock.patch.object(contracts, "cargo", return_value=subprocess.CompletedProcess([], 0, graph)) as cargo, \
                mock.patch("builtins.print"):
            contracts.managed_websocket()
        command = cargo.call_args.args[0]
        self.assertEqual(set(command[command.index("--features") + 1].split(",")), features)
        self.assertEqual(command[command.index("--edges") + 1], "normal,build")
        self.assertIn("--no-default-features", command)
        self.assertNotIn("--workspace", command)

    def test_core_candidate_leak_is_rejected_across_every_non_http_graph(self):
        for features in (None, {"websocket"}, {"managed", "websocket", "proxy", "tcp", "reconnect"},
                         {"cross-carrier-candidate", "tcp"}, {"cross-carrier-candidate", "tcp", "websocket"},
                         {"cross-carrier-candidate", "managed", "websocket", "proxy", "tcp", "reconnect"}):
            root = ",".join(sorted(features or ()))
            graph = f"syntra-net v1.0.0|{root}\nsyntra-core v1.0.0|http-candidate\n"
            with self.subTest(features=features):
                violations = contracts.graph_violations(graph, "syntra-net", no_tls_features=features)
                self.assertTrue(any("syntra-core/http-candidate" in value for value in violations))
        graph = "syntra-core v1.0.0|\nunrelated v0.1.0|http,http-candidate\n"
        self.assertEqual(contracts.graph_violations(graph, "syntra-core"), [])

    def test_http_graph_requires_candidate_core_and_rejects_ws_tls_and_state(self):
        graph = "syntra-net v1.0.0|http\nsyntra-core v1.0.0|http-candidate\ngetrandom v0.3.0|std\n"
        self.assertEqual(contracts.graph_violations(graph, "syntra-net", no_tls_features={"http"}), [])
        for dependency in ("rustls", "tokio-rustls", "rusqlite", "libsqlite3-sys", "fs2",
                           "tokio-tungstenite", "tungstenite", "http", "httparse"):
            with self.subTest(dependency=dependency):
                self.assertTrue(contracts.graph_violations(graph + f"{dependency} v1.0.0|\n", "syntra-net", no_tls_features={"http"}))
        for feature in ("websocket", "tls-rustls", "native-enrollment", "cross-carrier-candidate"):
            with self.subTest(feature=feature):
                self.assertTrue(contracts.graph_violations(graph + f"syntra-net v1.0.0|{feature}\n", "syntra-net", no_tls_features={"http"}))
        for missing in ("", "syntra-core v1.0.0|\n"):
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "did not enable syntra-core/http-candidate"):
                contracts.graph_violations("syntra-net v1.0.0|http\n" + missing, "syntra-net", no_tls_features={"http"})

    def test_http_lane_checks_standalone_and_managed_compositions_without_dev_graph(self):
        def run(command, root):
            features = command[command.index("--features") + 1]
            graph = f"syntra-net v1.0.0|{features}\nsyntra-core v1.0.0|http-candidate\n"
            return subprocess.CompletedProcess(command, 0, graph)
        with mock.patch.object(contracts, "cargo", side_effect=run) as cargo, mock.patch("builtins.print"):
            contracts.http()
        self.assertEqual(cargo.call_count, 3)
        selections = []
        for call in cargo.call_args_list:
            command = call.args[0]
            selections.append(set(command[command.index("--features") + 1].split(",")))
            self.assertEqual(command[command.index("--edges") + 1], "normal,build")
            self.assertIn("--no-default-features", command)
            self.assertNotIn("--workspace", command)
        self.assertEqual(selections, [{"http"}, {"managed", "http", "proxy", "tcp", "reconnect"},
                                     {"managed", "http", "websocket", "proxy", "tcp", "reconnect"}])

    def test_cross_carrier_graph_keeps_provider_wss_free_of_implicit_opt_ins(self):
        for features in ({"cross-carrier-candidate", "tcp"}, {"cross-carrier-candidate", "tcp", "websocket"}):
            graph = "syntra-net v1.0.0|" + ",".join(sorted(features)) + "\ntokio v1.0.0|net,io-util\n"
            with self.subTest(features=features):
                self.assertEqual(contracts.graph_violations(graph, "syntra-net", no_tls_features=features), [])
                for feature in ("managed", "http", "tls-rustls", "native-enrollment", "reconnect", "proxy"):
                    with self.subTest(extra_feature=feature):
                        self.assertTrue(contracts.graph_violations(graph + f"syntra-net v1.0.0|{feature}\n",
                                                                  "syntra-net", no_tls_features=features))
                for dependency in ("rustls", "tokio-rustls", "native-tls", "rusqlite", "libsqlite3-sys", "fs2"):
                    with self.subTest(dependency=dependency):
                        self.assertTrue(contracts.graph_violations(graph + f"{dependency} v1.0.0|\n",
                                                                  "syntra-net", no_tls_features=features))
                for package, tls_features in contracts.TLS_FEATURES.items():
                    for feature in tls_features:
                        with self.subTest(package=package, tls_feature=feature):
                            self.assertTrue(contracts.graph_violations(graph + f"{package} v1.0.0|{feature}\n",
                                                                      "syntra-net", no_tls_features=features))
                if "websocket" not in features:
                    for dependency in ("tokio-tungstenite", "tungstenite", "http", "httparse"):
                        with self.subTest(dependency=dependency):
                            self.assertTrue(contracts.graph_violations(graph + f"{dependency} v1.0.0|\n",
                                                                      "syntra-net", no_tls_features=features))
                for missing in features:
                    incomplete = "syntra-net v1.0.0|" + ",".join(sorted(features - {missing})) + "\n"
                    with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "did not enable"):
                        contracts.graph_violations(incomplete, "syntra-net", no_tls_features=features)

    def test_cross_carrier_feature_must_imply_tcp_without_selecting_it(self):
        for features in ({"cross-carrier-candidate"}, {"cross-carrier-candidate", "websocket"}):
            graph = "syntra-net v1.0.0|" + ",".join(sorted(features)) + "\n"
            with self.subTest(features=features):
                with self.assertRaisesRegex(ValueError, "did not enable syntra-net features:.*tcp"):
                    contracts.graph_violations(graph, "syntra-net", no_tls_features=features)
                self.assertEqual(contracts.graph_violations(graph + "syntra-net v1.0.0|tcp\n", "syntra-net",
                                                            no_tls_features=features), [])

    def test_cross_carrier_lane_separates_minimal_provider_and_explicit_compositions(self):
        def run(command, root):
            features = command[command.index("--features") + 1]
            graph = f"syntra-net v1.0.0|{features},tcp\n"
            if "http" in features.split(","):
                graph += "syntra-core v1.0.0|http-candidate\n"
            return subprocess.CompletedProcess(command, 0, graph)
        with mock.patch.object(contracts, "cargo", side_effect=run) as cargo, mock.patch("builtins.print"):
            contracts.cross_carrier_candidate()
        selections = []
        for call in cargo.call_args_list:
            command = call.args[0]
            selections.append(set(command[command.index("--features") + 1].split(",")))
            self.assertEqual(command[:2], ["tree", "--locked"])
            self.assertEqual(command[command.index("-p") + 1], "syntra-net")
            self.assertEqual(command[command.index("--edges") + 1], "normal,build")
            self.assertIn("--no-default-features", command)
            self.assertNotIn("--workspace", command)
        self.assertEqual(selections, [
            {"cross-carrier-candidate"},
            {"cross-carrier-candidate", "websocket"},
            {"cross-carrier-candidate", "managed", "websocket", "proxy", "tcp", "reconnect"},
            {"cross-carrier-candidate", "managed", "http", "websocket", "proxy", "tcp", "reconnect"},
        ])

    def test_cargo_is_locked_to_pinned_toolchain(self):
        with mock.patch.object(contracts.subprocess, "run") as run:
            contracts.cargo(["metadata", "--locked"])
        self.assertEqual(run.call_args.kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.88.0")
        self.assertTrue(run.call_args.kwargs["check"])


class PackagingTests(unittest.TestCase):
    def test_real_workspace_publishes_libraries_but_not_integration_fixtures(self):
        workspace = tomllib.loads((contracts.ROOT / "Cargo.toml").read_text())["workspace"]
        packages = {}
        for member in workspace["members"]:
            manifest = tomllib.loads((contracts.ROOT / member / "Cargo.toml").read_text())
            package = manifest["package"]
            packages[package["name"]] = package
        self.assertEqual({name for name, package in packages.items()
                          if package.get("publish") not in (False, [])},
                         {"syntra-core", "syntra-runtime", "syntra-net", "syntra-ffi"})
        self.assertIs(packages["syntra-integration"]["publish"], False)
        self.assertEqual(packages["syntra-net"]["publish"], ["crates-io"])

    def test_network_package_documents_tcp_without_changing_consumer_defaults(self):
        root = contracts.ROOT / "crates/syntra-net"
        manifest = tomllib.loads((root / "Cargo.toml").read_text())
        package = manifest["package"]
        self.assertEqual(package["repository"], {"workspace": True})
        self.assertEqual(package["documentation"], "https://docs.rs/syntra-net")
        self.assertTrue((root / package["readme"]).is_file())
        self.assertEqual((root / "LICENSE").read_bytes(), (contracts.ROOT / "LICENSE").read_bytes())
        self.assertEqual(manifest["features"]["default"], [])
        docs = package["metadata"]["docs"]["rs"]
        self.assertIn("tcp", docs["features"])
        self.assertEqual(docs["default-target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(docs["targets"], [])
        dependencies = manifest["target"]["cfg(not(target_arch = \"wasm32\"))"]["dependencies"]
        version = tomllib.loads((contracts.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        for name in ("syntra-core", "syntra-runtime"):
            self.assertEqual(dependencies[name]["version"], version)
            self.assertEqual(dependencies[name]["path"], "../" + name)

    def test_selects_workspace_members_not_registry_dependencies(self):
        metadata = {"workspace_members": ["core"], "packages": [
            {"id": "core", "name": "syntra-core", "publish": None}, {"id": "dep", "name": "dep"}]}
        with mock.patch.object(contracts, "cargo", return_value=subprocess.CompletedProcess([], 0, json.dumps(metadata))):
            self.assertEqual(set(contracts.workspace_packages()), {"syntra-core"})

    def test_packaging_obeys_publish_false_and_covers_new_public_members(self):
        packages = {name: {"publish": publish} for name, publish in [
            ("syntra-core", None), ("syntra-net", ["crates-io"]),
            ("syntra-integration", [])]}
        with mock.patch.object(contracts, "workspace_packages", return_value=packages), \
                mock.patch.object(contracts, "cargo") as cargo, mock.patch("builtins.print"):
            contracts.package_workspace()
        self.assertEqual(cargo.call_count, 2)
        self.assertEqual({call.args[0][3] for call in cargo.call_args_list}, {"syntra-core", "syntra-net"})
        self.assertTrue(all("--locked" in call.args[0] for call in cargo.call_args_list))
        # New workspace versions need not already exist on crates.io. Archive
        # lockfile resolution belongs to ordered publication, not contents CI.
        for call in cargo.call_args_list:
            self.assertEqual(call.args[0], ["package", "--locked", "-p", call.args[0][3], "--list"])
            self.assertFalse(call.kwargs["capture"])

    def test_empty_publish_set_is_not_a_pass(self):
        with mock.patch.object(contracts, "workspace_packages", return_value={}), self.assertRaises(ValueError):
            contracts.package_workspace()


class NativeFeatureExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load declarations only; these unit checks never launch Cargo.
        cls.target = runpy.run_path(str(contracts.ROOT / "crates/syntra-net/tests/target_contract.py"))

    def test_candidate_feature_is_checked_independently_and_rejected_on_wasm(self):
        self.assertEqual(self.target["FEATURES"], (
            "tcp", "http", "websocket", "tls-rustls", "reconnect", "managed", "proxy",
            "native-enrollment", "cross-carrier-candidate",
        ))
        contract = self.target["TargetContract"]
        for omit_candidate, success in ((False, True), (True, False)):
            native = [feature for feature in self.target["FEATURES"]
                      if not (omit_candidate and feature == "cross-carrier-candidate")]
            output = "error: syntra-net features " + ", ".join(native) + " " + self.target["NATIVE_ONLY"]
            with self.subTest(omit_candidate=omit_candidate), \
                    mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 101, "", output)) as run:
                result = unittest.TestResult()
                contract("test_wasm_native_features_report_the_actionable_boundary").run(result)
            self.assertEqual(result.wasSuccessful(), success, result.failures + result.errors)
            self.assertEqual(run.call_count, len(self.target["FEATURES"]) + 1)
            selections = []
            for call in run.call_args_list:
                command = call.args[0]
                self.assertEqual(command[:5], ["cargo", "check", "--locked", "-p", "syntra-net"])
                self.assertIn("--no-default-features", command)
                self.assertIn("--lib", command)
                self.assertEqual(command[command.index("--target") + 1], "wasm32-unknown-unknown")
                selections.append(command[command.index("--features") + 1])
            self.assertIn("cross-carrier-candidate", selections)

    def test_cross_carrier_matrix_executes_candidate_and_legacy_routes_in_both_graphs(self):
        self.assertEqual(set(self.target["CROSS_CARRIER_REGRESSIONS"]), {
            (features, ("--test", target))
            for features in ("managed,websocket,proxy,cross-carrier-candidate",
                             "managed,http,websocket,proxy,cross-carrier-candidate")
            for target in ("cross_carrier", "routes")
        })

    def test_cross_carrier_execution_rejects_empty_ignored_failed_and_summary_only_runs(self):
        contract = self.target["TargetContract"]
        for status, passed, failed, ignored, named, success in (
            (0, 3, 0, 0, True, True), (0, 0, 0, 0, False, False),
            (0, 0, 0, 3, False, False), (0, 3, 0, 1, True, False),
            (101, 3, 0, 0, True, False), (0, 3, 1, 0, True, False),
            (0, 3, 0, 0, False, False),
        ):
            names = (*self.target["CROSS_CARRIER_TESTS"], *self.target["CROSS_CARRIER_HTTP_TESTS"])
            output = "".join(f"test {name} ... ok\n" for name in names) if named else ""
            output += f"test result: ok. {passed} passed; {failed} failed; {ignored} ignored;\n"
            with self.subTest(status=status, passed=passed, failed=failed, ignored=ignored, named=named), \
                    mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], status, output, "")) as run, \
                    mock.patch("builtins.print"):
                result = unittest.TestResult()
                contract("test_cross_carrier_candidate_regressions_execute").run(result)
            self.assertEqual(result.wasSuccessful(), success, result.failures + result.errors)
            self.assertEqual(run.call_count, 4)
            for call, (features, selection) in zip(run.call_args_list, self.target["CROSS_CARRIER_REGRESSIONS"]):
                self.assertEqual(call.args[0], [
                    "cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                    "--features", features, *selection, "--", "--color", "never",
                ])

    def test_cross_carrier_execution_requires_each_named_behavior_not_just_other_tests(self):
        contract = self.target["TargetContract"]
        names = (*self.target["CROSS_CARRIER_TESTS"], *self.target["CROSS_CARRIER_HTTP_TESTS"])
        self.assertIn("supervised::automatic_tcp_to_provider_wss_and_back_both_authentication_modes", names)
        self.assertIn("supervised::automatic_tcp_to_real_provider_https_both_authentication_modes", names)
        self.assertIn("mixed_candidate_validates_unused_permissions_and_old_api_stays_homogeneous", names)
        for omitted in names:
            output = "".join(f"test {name} ... ok\n" for name in names if name != omitted)
            output += f"test result: ok. {len(names) - 1} passed; 0 failed; 0 ignored;\n"
            with self.subTest(omitted=omitted), \
                    mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")), \
                    mock.patch("builtins.print"):
                result = unittest.TestResult()
                contract("test_cross_carrier_candidate_regressions_execute").run(result)
            self.assertFalse(result.wasSuccessful())
            self.assertFalse(result.errors, result.errors)
            self.assertTrue(any(omitted in failure for _, failure in result.failures), result.failures)

    def test_matrix_selects_http_and_both_managed_websocket_compositions(self):
        self.assertIn("http", self.target["FEATURES"])
        matrix = set(self.target["REGRESSIONS"])
        self.assertIn(("http", ("--test", "http_records")), matrix)
        self.assertIn(("http", ("--lib", "http::")), matrix)
        for features in ("managed,websocket,proxy", "managed,tls-rustls,proxy"):
            for target in ("network_websocket", "routes"):
                with self.subTest(features=features, target=target):
                    self.assertIn((features, ("--test", target)), matrix)
        self.assertIn(("http", ("--test", "http_connections")), matrix)
        for features in ("managed,http,proxy", "managed,http,websocket,proxy"):
            for target in ("http_connections", "network_http", "routes"):
                with self.subTest(features=features, target=target):
                    self.assertIn((features, ("--test", target)), matrix)

    def test_exact_http_forward_execution_requires_the_named_single_test(self):
        contract = self.target["TargetContract"]
        tests = self.target["HTTP_PROXY_TESTS"]
        self.assertEqual(len(tests), 3)
        self.assertIn("candidate::proxied::socks_connect_and_real_forward_http_https_encrypted_rpc_both_modes", tests)
        for executed, count, success in ((tests[0], 1, True), ("other", 1, False), (tests[0], 0, False)):
            with self.subTest(executed=executed, count=count):
                output = f"test {executed} ... ok\ntest result: ok. {count} passed; 0 failed; 0 ignored;\n"
                result = unittest.TestResult()
                with mock.patch.dict(contract.test_http_proxy_regressions_execute_exactly.__globals__,
                                     {"HTTP_PROXY_TESTS": (tests[0],)}), \
                        mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
                    contract("test_http_proxy_regressions_execute_exactly").run(result)
                self.assertEqual(result.wasSuccessful(), success, result.failures + result.errors)
                self.assertEqual(run.call_count, 2)
                self.assertTrue(all("--exact" in call.args[0] for call in run.call_args_list))

    def test_core_matrix_requires_default_rejection_and_gated_golden_prologue(self):
        contract = self.target["TargetContract"]
        expected = self.target["CORE_CONTEXT_TESTS"]
        self.assertIn("default_rejects_all_four_candidate_rows_even_with_source_present", expected[None])
        self.assertIn("candidate::exact_golden_context_is_entire_noise_prologue_for_both_roles", expected["http-candidate"])
        for omit_default, success in ((False, True), (True, False)):
            def run(command, **kwargs):
                mode = "http-candidate" if "--features" in command else None
                names = expected[mode]
                if omit_default and mode is None:
                    names = names[:1]
                output = "".join(f"test {name} ... ok\n" for name in names)
                output += f"test result: ok. {len(names)} passed; 0 failed; 0 ignored;\n"
                return subprocess.CompletedProcess(command, 0, output, "")
            with self.subTest(omit_default=omit_default), mock.patch.object(subprocess, "run", side_effect=run) as cargo:
                result = unittest.TestResult()
                contract("test_core_candidate_context_regressions_execute").run(result)
            self.assertEqual(result.wasSuccessful(), success, result.failures + result.errors)
            self.assertEqual(cargo.call_count, 2)
            self.assertTrue(all(call.args[0][4] == "syntra-core" for call in cargo.call_args_list))

    def test_execution_contract_rejects_zero_ignored_and_failed_runs(self):
        contract = self.target["TargetContract"]
        for status, passed, ignored, success in ((0, 21, 0, True), (0, 0, 0, False),
                                                (0, 0, 21, False), (101, 21, 0, False)):
            with self.subTest(status=status, passed=passed, ignored=ignored):
                output = f"test result: ok. {passed} passed; 0 failed; {ignored} ignored;\n"
                case = contract("test_native_feature_regressions_execute")
                result = unittest.TestResult()
                with mock.patch.dict(contract.test_native_feature_regressions_execute.__globals__,
                                     {"REGRESSIONS": (("http", ("--test", "http_records")),)}), \
                        mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], status, output, "")) as run:
                    case.run(result)
                self.assertEqual(result.wasSuccessful(), success, result.failures + result.errors)
                self.assertEqual(run.call_args.args[0], [
                    "cargo", "test", "--locked", "-p", "syntra-net", "--no-default-features",
                    "--features", "http", "--test", "http_records", "--", "--color", "never",
                ])


if __name__ == "__main__":
    unittest.main()
