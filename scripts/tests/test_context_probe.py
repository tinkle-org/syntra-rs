import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import context_probe as probe
from local_inputs import ROOT, read_json
from protocol_contract import indexed, validate_number_types, verify_independent


class FixtureTests(unittest.TestCase):
    def test_contract_numbers_do_not_coerce_booleans_or_floats(self):
        validate_number_types({"authorization_key_bytes": 32}, {"scope": [34, None], "m2_bytes": 48})
        for limits, layout in (({"authorization_key_bytes": 32.0}, {}), ({}, {"scope_bytes": [True, 255]}),
                               ({}, {"domain": [False, 10]}), ({}, {"m2_bytes": 48.0})):
            with self.subTest(limits=limits, layout=layout), self.assertRaises(ValueError):
                validate_number_types(limits, layout)

    def test_independent_ids_cannot_share_context_bytes(self):
        rows = [{"id": str(i), "context_hex": f"{i:02x}"} for i in range(4)]
        verify_independent(rows, indexed(rows))
        rows[-1]['context_hex'] = rows[0]['context_hex']
        with self.assertRaisesRegex(ValueError, "duplicate independent Rust context bytes"):
            verify_independent(rows, indexed(rows))

    def test_index_requires_unique_nonempty_string_ids(self):
        rows = [{"id": "a"}, {"id": "b"}]
        self.assertEqual(indexed(rows), {"a": rows[0], "b": rows[1]})
        for bad in (None, {}, {"id": ""}, {"id": None}, {"id": 1}, {"id": True}, {"id": []}, rows[0]):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "fixture ID"):
                indexed([*rows, bad])

    def test_scope_byte_length_uses_character_count_without_changing_scope(self):
        layout = read_json(ROOT, "protocol-contract.json")["context_layout"]
        start, end = layout["scope_length_u16be"]
        scope = "é水"
        prefix = bytes(range(start))
        encoded = prefix + len(scope.encode()).to_bytes(2, "big") + scope.encode()
        base = {"scope": scope, "context_hex": encoded.hex()}
        mutated = probe.negative_bytes({"mutation": "scope-byte-length"}, base, layout)
        self.assertEqual(mutated[:start], prefix)
        self.assertEqual(mutated[start:end], b"\x00\x02")
        self.assertEqual(mutated[end:], scope.encode())


class RustSourceTests(unittest.TestCase):
    def test_block_ignores_braces_in_literals_and_comments_not_lifetimes(self):
        for body in ("let _ = b'}';", "let _ = '}';", r"let _ = ('\'', '\\', '\u{7d}');",
                     r'let _ = b"\" } /*";', 'let _ = br##"inner "# } //"##;',
                     'let _ = r#"quote " }"#;', '/* /* nested */ } */ // }',
                     "fn take<'a>(_: &'a str) {}", "'label: loop { break 'label; }"):
            expected = f"impl Demo {{\n    {body}\n}}"
            source = "/*\nimpl Demo {}\n*/\n" + expected + "\nfn after() {}"
            with self.subTest(body=body):
                self.assertEqual(probe.block(source, "impl Demo"), expected)

    def test_only_active_provider_guard_counts(self):
        contract = read_json(ROOT, "protocol-contract.json")
        native = probe.regular_file(ROOT, probe.NATIVE_WS)
        provider = probe.regular_file(ROOT, probe.NATIVE_TLS)
        guard = b"metadata.role != role"
        self.assertEqual(provider.count(guard), 1)
        for decoy in (b"false /* /* nested */ metadata.role != role */", b"false // metadata.role != role\n",
                      b'r#"metadata.role != role"# == ""'):
            edited = provider.replace(guard, decoy)
            with self.subTest(decoy=decoy), patch.object(probe, "regular_file", side_effect=[native, edited]), \
                    self.assertRaisesRegex(ValueError, "provider role"):
                probe.binding_sources(ROOT, contract)
