"""Default graph checks must not confuse dev/test dependencies with production."""

import json
from pathlib import Path
import subprocess
import sys
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
        self.assertEqual(contracts.ISOLATED_PACKAGES, ("syntra-core", "syntra-runtime", "syntra-transport"))
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
        with mock.patch.object(contracts, "workspace_packages", return_value={}), self.assertRaisesRegex(ValueError, "migration is incomplete"):
            contracts.isolation()

    def test_cargo_is_locked_to_pinned_toolchain(self):
        with mock.patch.object(contracts.subprocess, "run") as run:
            contracts.cargo(["metadata", "--locked"])
        self.assertEqual(run.call_args.kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.88.0")
        self.assertTrue(run.call_args.kwargs["check"])


class PackagingTests(unittest.TestCase):
    def test_selects_workspace_members_not_registry_dependencies(self):
        metadata = {"workspace_members": ["core"], "packages": [
            {"id": "core", "name": "syntra-core", "publish": None}, {"id": "dep", "name": "dep"}]}
        with mock.patch.object(contracts, "cargo", return_value=subprocess.CompletedProcess([], 0, json.dumps(metadata))):
            self.assertEqual(set(contracts.workspace_packages()), {"syntra-core"})

    def test_packaging_obeys_publish_false_and_covers_new_public_members(self):
        packages = {name: {"publish": publish} for name, publish in [
            ("syntra-core", None), ("syntra-transport", ["crates-io"]),
            ("syntra-integration", [])]}
        with mock.patch.object(contracts, "workspace_packages", return_value=packages), \
                mock.patch.object(contracts, "cargo") as cargo, mock.patch("builtins.print"):
            contracts.package_workspace()
        self.assertEqual(cargo.call_count, 4)
        self.assertEqual({call.args[0][3] for call in cargo.call_args_list}, {"syntra-core", "syntra-transport"})
        self.assertTrue(all("--locked" in call.args[0] for call in cargo.call_args_list))

    def test_empty_publish_set_is_not_a_pass(self):
        with mock.patch.object(contracts, "workspace_packages", return_value={}), self.assertRaises(ValueError):
            contracts.package_workspace()


if __name__ == "__main__":
    unittest.main()
