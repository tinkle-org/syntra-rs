"""Check native feature entry points and the documented wasm32 API boundary.

Run from the repository root with Python 3 and its Rust toolchain active:
python3 crates/syntra-transport/tests/target_contract.py
The wasm32-unknown-unknown Rust target must be installed.
"""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
FEATURES = ("tcp", "websocket", "reconnect", "native-enrollment")
WASM = "wasm32-unknown-unknown"
NATIVE_ONLY = (
    "syntra-transport features tcp, websocket, reconnect, and native-enrollment "
    "require a non-wasm32 target; disable these features for wasm32 and use "
    "syntra-web's browser-local driver"
)


def check(*arguments):
    return subprocess.run(
        ["cargo", "check", "--locked", "-p", "syntra-transport", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


class TargetContract(unittest.TestCase):
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
                result = check("--target", WASM, "--lib", "--features", feature)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(NATIVE_ONLY, output)
                self.assertNotIn("error[E", output, "unexpected Rust type or import error")


if __name__ == "__main__":
    unittest.main()
