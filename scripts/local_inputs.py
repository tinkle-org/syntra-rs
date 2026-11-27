"""Shared helpers for repository-owned protocol checks."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path("tests/interoperability/fixtures")


def digest(content):
    return hashlib.sha256(content).hexdigest()


def regular_file(root, name):
    current = root
    for part in Path(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symlinked implementation input: {name}")
    return current.read_bytes()


def read_json(root, name):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError(f'duplicate JSON key in {name}')
        return result
    return json.loads(regular_file(root, name), object_pairs_hook=unique)
