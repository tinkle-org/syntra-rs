"""Verify pin-reference consistency for the pinned upstream Syntra revision
and presence of local snapshot directories.

Ensures reproducible builds do not silently follow a floating upstream main:
- README.md, MIGRATION.md and buf.gen.yaml must reference the same pinned
  upstream commit.
- The snapshot-comment files must use pinned upstream URLs, not
  repository-relative paths that resolve to absent local files.

This checks reference consistency and directory presence only; it does not
compare snapshot file contents against the upstream commit.

Run: python3 scripts/check-upstream-pin.py
Requires Python 3 (stdlib only). No network access.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PINNED = "2a91da7fdb96f3e75badf07614c14e4f85c9ba1c"
PINNED_URL = f"https://github.com/tinkle-org/syntra/blob/{PINNED}"
PINNED_TREE = f"https://github.com/tinkle-org/syntra/tree/{PINNED}"
PINNED_COMMIT = f"https://github.com/tinkle-org/syntra/commit/{PINNED}"


def fail(message: str) -> int:
    print(f"Upstream pin check failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    migration = (ROOT / "MIGRATION.md").read_text(encoding="utf-8")
    buf_gen = (ROOT / "buf.gen.yaml").read_text(encoding="utf-8")
    buf_yaml = (ROOT / "buf.yaml").read_text(encoding="utf-8")
    envelope = (ROOT / "proto/syntra/v1/envelope.proto").read_text(encoding="utf-8")

    for name, text in [
        ("README.md", readme),
        ("MIGRATION.md", migration),
        ("buf.gen.yaml", buf_gen),
    ]:
        if PINNED not in text:
            return fail(f"{name} does not reference pinned upstream {PINNED}")

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

    # The three pin-link styles must all resolve to the same commit.
    urls = set(re.findall(r"https://github\.com/tinkle-org/syntra/(?:blob|tree|commit)/([0-9a-f]{40})", readme + migration + buf_gen + buf_yaml + envelope))
    if urls and urls != {PINNED}:
        return fail(f"mixed upstream pins found: {sorted(urls)} (expected only {PINNED})")

    # Local snapshot directories must exist; upstream authority stays remote.
    # This checks pin-reference consistency and directory presence only, not
    # snapshot contents against the pinned commit.
    for path in [ROOT / "proto", ROOT / "conformance/test-vectors"]:
        if not path.is_dir():
            return fail(f"missing local snapshot {path.relative_to(ROOT)}")
    # Pinned-URL convention: at least one pinned blob/tree link must exist.
    if PINNED_URL not in buf_yaml or PINNED_TREE not in (readme + migration):
        # README/MIGRATION use tree/commit links; buf comments use blob links.
        # Require the blob form in buf.yaml and any pinned form elsewhere.
        if PINNED_COMMIT not in (readme + migration):
            return fail("pinned upstream links missing")

    print(f"Upstream snapshot pin matches {PINNED}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        sys.exit(f"Upstream pin check failed: {error}")
