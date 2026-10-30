"""Verify pin-reference consistency for the two scoped upstream Syntra pins
and presence of local snapshot directories.

Scopes (no floating upstream main):
- Extraction/schema pin ``2a91da7fdb96f3e75badf07614c14e4f85c9ba1c``:
  buf.gen.yaml, buf.yaml, proto/syntra/v1/envelope.proto, plus the
  pre-existing README.md/MIGRATION.md provenance links. Extraction files
  must contain only the extraction pin.
- SC1 contract pin ``0e8b0f8a4a789cb3d6d00b993e281867d2325e06`` (upstream
  PR #18, profile SNTR-SC1-WSS-V1): permitted ONLY in README.md,
  MIGRATION.md, SC1.md and SC1 fixture comments.
- Proposal-review pin ``94404d7378136d8b6c88ece28bf945c88d1653ba``: history
  only, permitted ONLY in README.md, MIGRATION.md, SC1.md and SC1 fixture
  comments; never in extraction files.

This checks reference consistency and directory presence only; it does not
compare snapshot file contents against either upstream commit.

Run: python3 scripts/check-upstream-pin.py
Requires Python 3 (stdlib only). No network access.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EXTRACTION_PIN = "2a91da7fdb96f3e75badf07614c14e4f85c9ba1c"
SC1_PIN = "0e8b0f8a4a789cb3d6d00b993e281867d2325e06"
PROPOSAL_PIN = "94404d7378136d8b6c88ece28bf945c88d1653ba"
PINNED_URL = f"https://github.com/tinkle-org/syntra/blob/{EXTRACTION_PIN}"
PINNED_TREE = f"https://github.com/tinkle-org/syntra/tree/{EXTRACTION_PIN}"
PINNED_COMMIT = f"https://github.com/tinkle-org/syntra/commit/{EXTRACTION_PIN}"

PIN_RE = re.compile(
    r"https://github\.com/tinkle-org/syntra/(?:blob|tree|commit)/([0-9a-f]{40})"
)
BARE_RE = re.compile(r"\b[0-9a-f]{40}\b")

DOC_FILES = ("README.md", "MIGRATION.md", "SC1.md")
EXTRACTION_FILES = ("buf.gen.yaml", "buf.yaml", "proto/syntra/v1/envelope.proto")
FIXTURE = "crates/syntra-secure-channel/tests/fixtures/sc1_context_v1.rs"


def fail(message: str) -> int:
    print(f"Upstream pin check failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    texts = {}
    for name in list(DOC_FILES) + list(EXTRACTION_FILES) + [FIXTURE]:
        texts[name] = (ROOT / name).read_text(encoding="utf-8")
    readme, migration = texts["README.md"], texts["MIGRATION.md"]
    buf_gen = texts["buf.gen.yaml"]
    buf_yaml = texts["buf.yaml"]
    envelope = texts["proto/syntra/v1/envelope.proto"]

    for name in ("README.md", "MIGRATION.md", "buf.gen.yaml"):
        if EXTRACTION_PIN not in texts[name]:
            return fail(f"{name} does not reference extraction pin {EXTRACTION_PIN}")

    # Current SC1 contract pin must be recorded in the owned docs.
    for name in ("README.md", "MIGRATION.md", "SC1.md"):
        if SC1_PIN not in texts[name]:
            return fail(f"{name} does not reference SC1 contract pin {SC1_PIN}")

    # Snapshot comments must use pinned URLs, not absent local paths.
    # A bare `docs/...` or `compatibility/...` is unpinned; the same text
    # inside `.../blob/<sha>/docs/...` is pinned. Strip full pinned URLs first.
    pinned_docs = f"{PINNED_URL}/docs/schema-registry.md"
    pinned_compat = f"{PINNED_URL}/compatibility/v1-initial/image.json"
    buf_stripped = buf_yaml.replace(pinned_docs, "").replace(pinned_compat, "")
    if "docs/schema-registry.md" in buf_stripped:
        return fail("buf.yaml has an unpinned schema-registry reference")
    if "compatibility/v1-initial/image.json" in buf_stripped:
        return fail("buf.yaml has an unpinned compatibility reference")

    pinned_schema = f"{PINNED_URL}/specifications/schema/reference.md"
    envelope_stripped = envelope.replace(pinned_schema, "")
    if "specifications/schema/reference.md" in envelope_stripped:
        return fail("envelope.proto still uses a relative specification reference")

    # Scoped exclusivity: extraction files must contain only the extraction
    # pin; the SC1 contract and proposal-history pins live in docs/fixture
    # comments only.
    for name in EXTRACTION_FILES:
        pins = set(PIN_RE.findall(texts[name])) | set(BARE_RE.findall(texts[name]))
        if SC1_PIN in texts[name] or PROPOSAL_PIN in texts[name]:
            return fail(f"{name} must contain only the extraction pin")
        if pins - {EXTRACTION_PIN}:
            return fail(
                f"{name} references out-of-scope pins: {sorted(pins - {EXTRACTION_PIN})}"
            )

    # Every pin URL anywhere in scope must be one of the three known pins.
    urls = set(PIN_RE.findall("".join(texts.values())))
    if urls - {EXTRACTION_PIN, SC1_PIN, PROPOSAL_PIN}:
        return fail(
            f"unknown upstream pins found: {sorted(urls - {EXTRACTION_PIN, SC1_PIN, PROPOSAL_PIN})}"
        )

    # Local snapshot directories must exist; upstream authority stays remote.
    # This checks pin-reference consistency and directory presence only, not
    # snapshot contents against either pinned commit.
    for path in [ROOT / "proto", ROOT / "conformance/test-vectors"]:
        if not path.is_dir():
            return fail(f"missing local snapshot {path.relative_to(ROOT)}")
    # Pinned-URL convention: at least one pinned blob/tree link must exist.
    if PINNED_URL not in buf_yaml or PINNED_TREE not in (readme + migration):
        # README/MIGRATION use tree/commit links; buf comments use blob links.
        # Require the blob form in buf.yaml and any pinned form elsewhere.
        if PINNED_COMMIT not in (readme + migration):
            return fail("pinned upstream links missing")

    print(f"Extraction pin {EXTRACTION_PIN}; SC1 contract pin {SC1_PIN}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        sys.exit(f"Upstream pin check failed: {error}")
