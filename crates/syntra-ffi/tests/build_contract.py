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

    def abi_symbols(self):
        names = {line.split()[-1].removeprefix("_")
                 for line in self.symbols().splitlines() if line.split()}
        return {name for name in names if name.startswith("syntra_")}

    def test_default_artifact_has_no_abi(self):
        result = self.cargo("build", "--locked", "-p", "syntra-ffi", "--no-default-features")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.abi_symbols(), set())

    def test_fixture_and_production_cannot_be_combined(self):
        result = self.cargo(
            "check", "--locked", "-p", "syntra-ffi", "--no-default-features",
            "--features", "production,test-fixture",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutually exclusive ABI modes", result.stderr)
        for headers in [
            ["syntra.h", "syntra_production.h"],
            ["syntra_production.h", "syntra.h"],
        ]:
            result = subprocess.run(
                ["cc", "-x", "c", "-std=c11", "-fsyntax-only",
                 "-DSYNTRA_TEST_FIXTURE", "-I", str(ROOT / "crates/syntra-ffi/include"),
                 "-include", headers[0], "-include", headers[1], "/dev/null"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mutually exclusive ABI modes", result.stderr)

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
            "build", "--locked", "-p", "syntra-ffi", "--no-default-features",
            "--features", "production",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("syntra_open", self.symbols())
        self.assertNotIn("syntra_v2_", self.symbols())
        self.assertNotIn("syntra_ffi_", self.symbols())
        self.assertNotIn("syntra_abi_compatible", self.symbols())
        expected = {
            "syntra_abi_version",
            "syntra_capabilities",
            "syntra_client_open",
            "syntra_client_open_clock",
            "syntra_host_open",
            "syntra_host_open_clock",
            "syntra_suspend",
            "syntra_platform_wake",
            "syntra_handshake",
            "syntra_call",
            "syntra_cancel",
            "syntra_poll",
            "syntra_receipt",
            "syntra_ingest",
            "syntra_emit",
            "syntra_emitted",
            "syntra_take_dispatch",
            "syntra_dispatch_cancelled",
            "syntra_complete",
            "syntra_notify",
            "syntra_next_notification",
            "syntra_withdraw",
            "syntra_status",
            "syntra_shutdown",
            "syntra_transport_closed",
            "syntra_shutdown_poll",
            "syntra_destroy",
            "syntra_free",
            "syntra_recovery_attach",
            "syntra_recovery_negotiate",
            "syntra_recovery_subscribe",
            "syntra_recovery_step",
            "syntra_recovery_poll",
            "syntra_recovery_result_free",
            "syntra_storage_take",
            "syntra_storage_complete",
            "syntra_storage_request_free",
        }
        # Exact production ABI 1 allowlist: only documented syntra_* exports.
        self.assertEqual(self.abi_symbols(), expected)
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

        recovery = self.cargo(
            "test", "--locked", "-p", "syntra-ffi", "--no-default-features",
            "--features", "production", "c_recovery", "--", "--nocapture",
        )
        self.assertEqual(recovery.returncode, 0, recovery.stdout + recovery.stderr)

    def test_explicit_native_fixture_exports_abi(self):
        result = self.cargo(
            "build", "--locked", "-p", "syntra-ffi", "--no-default-features",
            "--features", "test-fixture",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("syntra_client_open", self.symbols())
        self.assertNotIn("syntra_host_open", self.symbols())
        self.assertNotIn("syntra_capabilities", self.symbols())
        self.assertNotIn("syntra_recovery_", self.symbols())
        self.assertNotIn("syntra_ffi_", self.symbols())
        self.assertNotIn("syntra_v2_", self.symbols())
        self.assertEqual(self.abi_symbols(), {
            "syntra_abi_version", "syntra_abi_compatible", "syntra_open",
            "syntra_handshake", "syntra_call", "syntra_cancel", "syntra_cancel_current",
            "syntra_poll_notify", "syntra_close", "syntra_free", "syntra_last_error",
        })
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

    def test_production_headers_standalone_c_cpp_and_wasm_rejection(self):
        for header in ["syntra_production.h", "syntra_recovery.h"]:
            for language, standard in [("c", "c11"), ("c++", "c++17")]:
                result = subprocess.run(
                    ["cc", "-x", language, f"-std={standard}", "-Wall", "-Wextra",
                     "-Werror", "-fsyntax-only", "-include",
                     str(ROOT / "crates/syntra-ffi/include" / header),
                     "/dev/null"], capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(
            ["cc", "-x", "c", "-std=c11", "-fsyntax-only", "-D__wasm__",
             "-include", str(ROOT / "crates/syntra-ffi/include/syntra_production.h"),
             "/dev/null"], capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("syntra-ffi does not support WASM", result.stderr)


if __name__ == "__main__":
    unittest.main()
