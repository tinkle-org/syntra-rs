"""Native artifact / unsupported-target regression checks.

Run: python3 crates/syntra-ffi/tests/build_contract.py
Requires Cargo, nm, a C compiler, and the installed wasm32-unknown-unknown target.
Builds in an isolated temporary target directory; never consumes stale binaries.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class BuildContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="syntra-ffi-contract-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.target = Path(cls.temp.name)

    def cargo(self, *args):
        return subprocess.run(
            ["cargo", *args], cwd=ROOT, text=True, capture_output=True,
            env={**os.environ, "CARGO_TARGET_DIR": str(self.target)},
            timeout=180,
        )

    def symbols(self):
        if sys.platform == "darwin":
            library = self.target / "debug/libsyntra_ffi.dylib"
            command = ["nm", "-gU", str(library)]
        elif sys.platform.startswith("linux"):
            library = self.target / "debug/libsyntra_ffi.so"
            command = ["nm", "-D", "--defined-only", str(library)]
        else:
            self.skipTest("symbol check requires Darwin or Linux nm")
        return subprocess.run(command, text=True, capture_output=True, check=True).stdout

    def test_default_artifact_has_no_abi(self):
        result = self.cargo("build", "-p", "syntra-ffi", "--no-default-features")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("syntra_open", self.symbols())
        self.assertNotIn("syntra_abi_compatible", self.symbols())
        self.assertNotIn("syntra_ffi_client_open", self.symbols())
        self.assertNotIn("syntra_ffi_host_open", self.symbols())

    def test_blocking_wasm_builds_fail_with_actionable_diagnostic(self):
        for features in [[], ["--features", "test-fixture"], ["--features", "production"]]:
            with self.subTest(features=features):
                result = self.cargo(
                    "build", "--locked", "-p", "syntra-ffi", "--no-default-features",
                    "--target", "wasm32-unknown-unknown", *features,
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn("syntra-ffi does not support WASM", result.stderr)

    def test_explicit_production_exports_abi(self):
        result = self.cargo(
            "build", "-p", "syntra-ffi", "--no-default-features",
            "--features", "production",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("syntra_open", self.symbols())
        for symbol in [
            "syntra_ffi_abi_version",
            "syntra_ffi_free",
            "syntra_ffi_client_open",
            "syntra_ffi_client_hello_frame",
            "syntra_ffi_client_activate",
            "syntra_ffi_client_on_frame",
            "syntra_ffi_client_begin_call",
            "syntra_ffi_host_open",
            "syntra_ffi_host_accept_hello",
            "syntra_ffi_host_auth_complete",
            "syntra_ffi_host_on_frame",
            "syntra_ffi_host_take_pending",
            "syntra_ffi_host_answer",
            "syntra_ffi_host_notify",
            "syntra_ffi_host_next_outbound",
        ]:
            self.assertIn(symbol, self.symbols())
        executable = self.target / "production-smoke"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT / "crates/syntra-ffi/include"),
             str(ROOT / "crates/syntra-ffi/tests/production_smoke.c"),
             "-L", str(self.target / "debug"), "-lsyntra_ffi",
             f"-Wl,-rpath,{self.target / 'debug'}", "-o", str(executable)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run([str(executable)], check=True, timeout=30)

    def test_explicit_native_fixture_exports_abi(self):
        result = self.cargo(
            "build", "-p", "syntra-ffi", "--no-default-features",
            "--features", "test-fixture",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("syntra_ffi_client_open", self.symbols())
        self.assertNotIn("syntra_ffi_host_open", self.symbols())
        for symbol in ["syntra_open", "syntra_call", "syntra_poll_notify", "syntra_free"]:
            self.assertIn(symbol, self.symbols())
        executable = self.target / "fixture-smoke"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DSYNTRA_TEST_FIXTURE",
             "-I", str(ROOT / "crates/syntra-ffi/include"),
             str(ROOT / "crates/syntra-ffi/tests/fixture_smoke.c"),
             "-L", str(self.target / "debug"), "-lsyntra_ffi",
             f"-Wl,-rpath,{self.target / 'debug'}", "-o", str(executable)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run([str(executable)], check=True, timeout=30)

    def test_header_requires_native_fixture_opt_in(self):
        for defines, diagnostic in [
            ([], "syntra.h is test-only"),
            (["-DSYNTRA_TEST_FIXTURE", "-D__wasm__"], "syntra-ffi does not support WASM"),
        ]:
            with self.subTest(defines=defines):
                result = subprocess.run(
                    ["cc", "-std=c11", "-fsyntax-only", *defines,
                     "-I", str(ROOT / "crates/syntra-ffi/include"),
                     str(ROOT / "crates/syntra-ffi/tests/fixture_smoke.c")],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)


if __name__ == "__main__":
    unittest.main()
